# -*- coding: utf-8 -*-
"""TCP Datagram Reassembly
=============================

.. module:: pcapkit.foundation.reassembly.tcp

:mod:`pcapkit.foundation.reassembly.tcp` contains
:class:`~pcapkit.foundation.reassembly.tcp.TCP` only,
which reconstructs fragmented TCP packets back to origin.

"""
import math
import sys
from typing import TYPE_CHECKING

from pcapkit.foundation.reassembly.data.data import Completion, Deferred
from pcapkit.foundation.reassembly.data.tcp import (Buffer, BufferID, Datagram, DatagramID,
                                                    Fragment, HoleDescriptor, Packet)
from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
from pcapkit.protocols.transport.tcp import TCP as TCP_Protocol

if TYPE_CHECKING:
    from typing import Type

__all__ = ['TCP']


class TCP(ReassemblyBase[Packet, Datagram, BufferID, Buffer]):
    """Reassembly for TCP payload.

    Args:
        strict: if :data:`True`, report a datagram that is not completely
            reassembled as the tuple of its received runs; otherwise as one
            contiguous payload, its holes zero-filled
        store: if store reassembled datagram in memory, i.e.,
            :attr:`self._dtgram <pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram>`
            (if not, datagram will be discarded after callback)
        timeout: reassembly timeout in seconds, on the capture's own clock;
            :data:`None` selects :attr:`__timeout__`, which for TCP disables
            expiry

    Example:
        >>> from pcapkit.foundation.reassembly import TCP
        # Initialise instance:
        >>> tcp_reassembly = TCP()
        # Call reassembly:
        >>> tcp_reassembly(packet_dict)
        # Fetch result:
        >>> result = tcp_reassembly.datagram

    Note:
        There are two coordinate systems in play here, and keeping them apart
        matters. Sequence numbers -- in the :term:`hole descriptor list
        <reasm.tcp.buffer>` of :rfc:`815`, and in each payload buffer's own
        :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment.gap` and
        :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment.conflict` lists
        -- are kept **unwrapped**, inclusive of both bounds: every arriving
        sequence number is read modulo ``2 ** 32`` relative to the data
        already buffered under its buffer ID, per :rfc:`9293#section-3.4`, and
        placed on one unbounded integer line. A connection that crosses
        ``2 ** 32`` therefore continues at ``2 ** 32`` rather than back at
        zero. A payload buffer, on the other hand, is indexed from zero, such
        that
        :attr:`buffer.raw[n] <pcapkit.foundation.reassembly.data.tcp.Fragment.raw>`
        holds the octet with sequence number
        :attr:`buffer.isn <pcapkit.foundation.reassembly.data.tcp.Fragment.isn>`
        ``+ n``. :meth:`submit` converts between the two, subtracting that
        buffer's initial sequence number from each gap bound, and reports
        conflict ranges reduced back to modulo ``2 ** 32``.

        The hole descriptor list is held once per buffer ID, across every
        acknowledgement number's payload buffer, so it describes the *stream*
        rather than any one payload buffer: it decides when a stream whose FIN
        has been seen is whole and may be submitted. Whether each payload
        buffer is complete is a question about that buffer alone, answered
        from its own
        :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment.gap` list.

    Warning:
        **Limitation.** Without the handshake the start of a stream is unknown,
        so a FIN is taken to complete the stream once every octet from the
        lowest one seen so far up to the FIN has arrived. Data that arrives
        later but lies *below* everything seen before that FIN therefore opens
        a buffer of its own, and the first buffer has already been reported
        :attr:`~pcapkit.foundation.reassembly.data.data.Completion.COMPLETE`
        although the stream was not: ``[seq 1000 A*5, FIN 1005, seq 990 B*10]``
        gives ``B*10`` and ``A*5`` as two datagrams. This applies only to a
        buffer begun without a SYN: once the SYN is captured, the stream's
        start is the SYN's own sequence number, and a FIN completes the
        stream only when every octet from there up to the FIN has arrived.

    """
    if TYPE_CHECKING:
        protocol: 'Type[TCP_Protocol]'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol name of current reassembly object.
    __protocol_name__ = 'TCP'
    #: Protocol of current reassembly object.
    __protocol_type__ = TCP_Protocol

    #: float: Default reassembly timeout -- **disabled**, unlike IPv4 and IPv6.
    #:
    #: No specification gives TCP stream reassembly a deadline the way
    #: :rfc:`1122#section-3.3.2` and :rfc:`8200#section-4.5` give IP
    #: fragmentation one, and the numbers that look like candidates are not
    #: reassembly timeouts: the Maximum Segment Lifetime of
    #: :rfc:`9293#section-3.4.1` bounds how long a *segment* may linger in the
    #: network, and the user timeout of :rfc:`9293#section-3.8.3` aborts a
    #: connection whose data goes unacknowledged. Picking either as a default
    #: would silently discard buffered stream data on captures that are merely
    #: idle -- a long-lived connection with a two-minute lull is ordinary, while
    #: a 60-second gap between fragments of one IP datagram is pathological.
    #:
    #: So the mechanism is available and the default is off: pass ``timeout`` to
    #: ask for one, e.g. ``2 * 120`` for 2·MSL if that is the policy wanted.
    __timeout__ = math.inf

    #: int: Widest gap, in octets, that merging a segment into the payload
    #: buffer it is read against may zero-fill: 16 MiB. The gap is measured on
    #: whichever side the segment lands, from the buffer's end to the
    #: segment's start, or from the segment's end to the buffer's start.
    #:
    #: A segment can only legitimately open a gap as wide as the data in flight,
    #: which the receive window bounds. :rfc:`7323` allows windows up to
    #: ``2 ** 30``, but zero-filling a gap that wide costs 1 GiB, and real
    #: windows are far smaller -- Linux's default ``net.ipv4.tcp_rmem`` ceiling
    #: is 6 MiB -- so 16 MiB clears them with room to spare. A segment that
    #: would open a wider gap is not padded to; the buffer held so far is
    #: submitted and a fresh one opened for the segment instead. What that
    #: means depends on whether the buffer's SYN was captured:
    #:
    #: * **No SYN** -- the segment is taken to start a new stream on a reused
    #:   4-tuple, and the two buffers are reported independently.
    #: * **SYN captured** -- the SYN proves both are the same stream with the
    #:   range in between lost, so that range is recorded in the
    #:   :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment.gap` of the
    #:   payload buffer the segment was read against and of the new one, and
    #:   both are reported
    #:   :attr:`~pcapkit.foundation.reassembly.data.data.Completion.PARTIAL`
    #:   (in strict mode, as a single run each). The new buffer keeps the
    #:   SYN's header and counts as having seen it.
    #:
    #: Override in a subclass to change the bound.
    __window__ = 1 << 24

    ##########################################################################
    # Methods.
    ##########################################################################

    def reassembly(self, info: 'Packet') -> 'None':
        """Reassembly procedure.

        Arguments:
            info: :term:`info <reasm.tcp.packet>` dict of packets to be reassembled

        """
        # clear cache
        self._flag_n = False
        self.__cached__.clear()

        BUFID = info.bufid   # Buffer Identifier
        DSN = info.dsn       # Data Sequence Number
        ACK = info.ack       # Acknowledgement Number
        FIN = info.fin       # Finish Flag (Termination)
        RST = info.rst       # Reset Connection Flag (Termination)
        SYN = info.syn       # Synchronise Flag (Establishment)
        TS = info.timestamp  # Capture timestamp, i.e. the only clock we have

        # This segment's arrival is the evidence that capture time has reached
        # ``TS``. Off by default for TCP -- see ``__timeout__`` -- in which case
        # this returns immediately.
        self._dtgram.extend(self.expire(TS))

        # Sequence number of the first octet of this segment's payload. A SYN
        # occupies a sequence number of its own (:rfc:`793`), so payload sent
        # by or after a SYN starts at ``dsn + 1`` rather than at ``dsn``.
        # Without this the octet the SYN spends becomes a zero byte at the head
        # of the payload buffer, and every complete datagram of a connection
        # whose handshake was captured comes back one octet too long.
        PSN = DSN + 1 if SYN else DSN

        # when SYN is set, reset buffer of existing session
        if SYN and BUFID in self._buffer:
            self._dtgram.extend(
                self.submit(self._buffer.pop(BUFID), bufid=BUFID)
            )

        # Read the sequence number modulo 2**32 relative to the end of the data
        # it most plausibly continues -- this ACK's own payload buffer, or else
        # the most recently opened one -- per :rfc:`9293#section-3.4`. Plain
        # integer comparison reads a stream crossing 2**32 as a gap of about
        # 4 GiB. A segment landing farther than ``__window__`` outside that
        # buffer starts a new stream instead -- see ``__window__``.
        SHIFT = 0
        HDR = info.header if SYN else b''  # header of the buffer opened below, if any
        ANCHORED = SYN                     # whether that buffer's stream start is known
        MISSING = []  # type: list[tuple[int, int]] # range a split left out of it
        if BUFID in self._buffer:
            buffer = self._buffer[BUFID]
            fragment = buffer.ack.get(ACK)
            if fragment is None:
                fragment = next(reversed(buffer.ack.values()))
            END = fragment.isn + fragment.len
            UNWRAPPED = self._unwrap(PSN, END)
            # the zero-filled gap merging this segment would open, either side
            if max(UNWRAPPED - END, fragment.isn - (UNWRAPPED + info.len)) > self.__window__:
                old = self._buffer.pop(BUFID)
                if self._anchored(old):
                    # The SYN proves this is still the same stream, with the
                    # range in between lost. Both halves record that range as
                    # missing, so each is reported PARTIAL rather than COMPLETE.
                    MISSING.append((END, UNWRAPPED - 1) if UNWRAPPED > END
                                   else (UNWRAPPED + info.len, fragment.isn - 1))
                    fragment.gap.extend(MISSING)
                    HDR, ANCHORED, PSN = old.hdr, True, UNWRAPPED
                self._dtgram.extend(self.submit(old, bufid=BUFID))
            else:
                SHIFT = UNWRAPPED - PSN
                PSN = UNWRAPPED

        # initialise buffer with BUFID & ACK
        if BUFID not in self._buffer:
            hdl = [
                HoleDescriptor(
                    # everything from the octet after this segment onwards is
                    # still missing
                    first=PSN + info.len,
                    last=sys.maxsize,
                ),
            ]
            if not ANCHORED:
                # Without the handshake the stream's start is unknown, so what
                # lies below this segment is open too. The sentinel lower bound
                # marks this one hole as "before the capture began" rather than
                # as data missing from the stream; it is what lets a segment
                # arriving *below* this one leave a real hole between the two.
                hdl.insert(0, HoleDescriptor(first=-sys.maxsize, last=PSN - 1))
            self._buffer[BUFID] = Buffer(
                hdl=hdl,
                hdr=HDR,
                ack={
                    ACK: Fragment(
                        ind=[
                            info.num,
                        ],
                        isn=PSN,
                        len=info.len,
                        raw=info.payload,
                        # this segment's own payload is, by definition, all
                        # real; a split stream also records what it left out
                        gap=MISSING,
                        conflict=[],
                    ),
                },
                timestamp=TS,
            )
        else:
            # initialise buffer with ACK
            if ACK not in buffer.ack:
                buffer.ack[ACK] = Fragment(
                    ind=[
                        info.num,
                    ],
                    isn=PSN,
                    len=info.len,
                    raw=info.payload,
                    gap=[],
                    conflict=[],
                )
            else:
                # put header into header buffer
                if SYN:  # pragma: no cover
                    buffer.__update__(hdr=info.header)

                # append packet index
                fragment = buffer.ack[ACK]
                fragment.ind.append(info.num)

                # record fragment payload
                if PSN >= fragment.isn:  # if fragment goes after existing payload
                    self._reassemble_append(info, fragment, PSN)
                else:                    # if fragment exceeds existing payload
                    self._reassemble_prepend(info, fragment, PSN)

            # update hole descriptor list
            #
            # A segment carrying no payload -- a bare acknowledgement, SYN, FIN
            # or RST -- fills no hole, so it must not be run through the
            # :rfc:`815` algorithm: its ``last`` lies one below its ``first``,
            # and letting that through would split whichever hole contains it
            # into two adjacent holes covering the very same octets, growing
            # the list without bound on a long-lived connection.
            if info.len > 0:
                self._update_hole_descriptors(BUFID, info.first + SHIFT, info.last + SHIFT)

        # A FIN fixes the end of the stream at the sequence number it occupies,
        # and nothing more: data sent before it may still arrive after it. So
        # the open-ended hole is cut back to end there, and the buffer is
        # submitted once every octet below the FIN has arrived -- here, or on
        # whichever later segment closes the last hole -- or else when the
        # capture ends.
        if FIN:
            self._close_hole_descriptors(BUFID, PSN + info.len)

        # An RST, unlike a FIN, aborts the connection: :rfc:`9293#section-3.10.7.4`
        # has the receiver flush its segment queues and enter CLOSED, so it
        # accepts nothing sent before the RST that arrives after it. The buffer
        # is therefore submitted at once, as the receiver last saw it.
        if RST or self._stream_whole(BUFID):
            self._dtgram.extend(
                self.submit(self._buffer.pop(BUFID), bufid=BUFID)
            )

    @staticmethod
    def _unwrap(seq: 'int', ref: 'int') -> 'int':
        """Place a 32-bit sequence number on the unwrapped line near ``ref``.

        Arguments:
            seq: sequence number as carried on the wire, i.e. modulo 2**32
            ref: unwrapped sequence number the segment is expected to be near

        Returns:
            The integer congruent to ``seq`` modulo 2**32 that lies within
            2**31 of ``ref``, which is how :rfc:`9293#section-3.4` compares
            sequence numbers.

        """
        return ref + (seq - ref + 0x80000000) % 0x100000000 - 0x80000000

    @staticmethod
    def _anchored(buf: 'Buffer') -> 'bool':
        """Whether a buffer's stream start is known, i.e. its SYN was captured.

        Arguments:
            buf: :term:`buffer <reasm.tcp.buffer>` to look at

        Returns:
            :data:`False` exactly when the hole descriptor list still opens
            with the sentinel hole that a buffer begun without a SYN carries.

        """
        return not (buf.hdl and buf.hdl[0].first == -sys.maxsize)

    def _stream_whole(self, BUFID: 'BufferID') -> 'bool':
        """Whether a stream has seen its FIN and every octet below it.

        Arguments:
            BUFID: buffer identifier of the stream

        Returns:
            :data:`True` once a FIN has cut back the open-ended hole and the
            only hole left, if any, is the sentinel one below the first octet
            of a capture that missed the handshake.

        """
        for hole in self._buffer[BUFID].hdl:
            if hole.first != -sys.maxsize or hole.last == sys.maxsize:
                return False
        return True

    def _close_hole_descriptors(self, BUFID: 'BufferID', end: 'int') -> 'None':
        """Cut the hole descriptor list back to end below a FIN.

        Arguments:
            BUFID: buffer identifier of the stream
            end: unwrapped sequence number the FIN occupies, i.e. one past the
                last octet of the stream

        """
        HDL = self._buffer[BUFID].hdl
        HDL[:] = [
            hole if hole.last < end else HoleDescriptor(first=hole.first, last=end - 1)
            for hole in HDL if hole.first < end
        ]

    def _reassemble_append(self, info: 'Packet', fragment: 'Fragment', PSN: 'int') -> 'None':
        """Merge a segment that starts at or after the buffered payload's end.

        Covers both an ordinary (or zero-length) forward gap and a tail-side
        overlap. Mutates ``fragment`` in place: its ``gap`` list, its
        ``conflict`` list, and finally its ``raw``/``len`` via
        :meth:`~pcapkit.foundation.reassembly.data.data.Info.__update__`.

        Arguments:
            info: :term:`info <reasm.tcp.packet>` dict of the arriving segment
            fragment: this ACK bucket's own
                :class:`~pcapkit.foundation.reassembly.data.tcp.Fragment`
            PSN: payload sequence number of the arriving segment

        """
        ISN = fragment.isn       # Initial Sequence Number
        RAW = fragment.raw       # Raw Payload Data
        GAPS = fragment.gap      # this fragment's own gap list
        LEN = fragment.len
        GAP = PSN - (ISN + LEN)  # gap length between payloads
        if GAP >= 0:             # if fragment goes after existing payload
            if GAP > 0:
                GAPS.append((ISN + LEN, PSN - 1))
            RAW += bytearray(GAP) + info.payload
        else:
            # Fragment partially overlaps existing payload. Per
            # :rfc:`9293#section-3.10` ("we reconstruct the segment
            # to contain just the new data"), an already-*received*
            # byte wins over a conflicting arriving one; only a
            # position this *fragment* has not received yet (per
            # its own ``gap`` list, not the buffer-wide ``HDL`` --
            # see
            # :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment.gap`)
            # has nothing to disagree with, so the arriving byte
            # is simply accepted there -- an ordinary gap fill,
            # not a conflict.
            OFFSET = PSN - ISN                     # index into RAW where the overlap begins
            OVERLAP = min(info.len, LEN - OFFSET)  # length of the overlapping range
            merged, conflicts = self._merge_overlap(
                GAPS,
                bytes(RAW[OFFSET:OFFSET + OVERLAP]), bytes(info.payload[:OVERLAP]),
                PSN,
            )
            RAW[OFFSET:OFFSET + OVERLAP] = merged
            fragment.conflict.extend(conflicts)
            if info.len > OVERLAP:  # fragment reaches past the buffered end
                RAW += info.payload[OVERLAP:]
        self._trim_gaps(GAPS, PSN, PSN + info.len - 1)
        fragment.__update__(
            raw=RAW,       # update payload datagram
            len=len(RAW),  # update payload length
        )

    def _reassemble_prepend(self, info: 'Packet', fragment: 'Fragment', PSN: 'int') -> 'None':
        """Merge a segment that starts before the buffered payload's own ``isn``.

        Revises this fragment's ``isn`` down to ``PSN``, then covers both an
        ordinary (or zero-length) reach-back gap and a head-side overlap --
        which may also extend a new tail past the buffered end in the same
        call. Mutates ``fragment`` in place: its ``isn``, its ``gap`` list,
        its ``conflict`` list, and finally its ``raw``/``len`` via
        :meth:`~pcapkit.foundation.reassembly.data.data.Info.__update__`.

        Arguments:
            info: :term:`info <reasm.tcp.packet>` dict of the arriving segment
            fragment: this ACK bucket's own
                :class:`~pcapkit.foundation.reassembly.data.tcp.Fragment`
            PSN: payload sequence number of the arriving segment

        """
        ISN = fragment.isn       # Initial Sequence Number, before revision
        RAW = fragment.raw       # Raw Payload Data
        GAPS = fragment.gap      # this fragment's own gap list
        LEN = info.len
        GAP = ISN - (PSN + LEN)  # gap length between payloads
        fragment.__update__(
            isn=PSN,
        )
        if GAP >= 0:             # if fragment exceeds existing payload
            if GAP > 0:
                GAPS.append((PSN + LEN, ISN - 1))
            RAW = info.payload + bytearray(GAP) + RAW
        else:
            # Mirrored reach-back case: the fragment starts before
            # ``ISN`` and its tail overlaps the start of the
            # already-buffered payload. Same resolution -- keep
            # already-received bytes, fill any gap among them from
            # the arriving segment, and prepend the genuinely new
            # head. The new head-prepend below is *not* mutually
            # exclusive with the rare case of also appending a new
            # tail past the buffered end (full engulfment plus
            # extension) -- both can happen in the same call, since
            # they come from independent ends of the fragment. What
            # *is* mutually exclusive is which one of the old tail
            # (``RAW[OVERLAP:]``) or a genuinely new one
            # (``info.payload[OFFSET + OVERLAP:]``) is non-empty --
            # never both, since ``OVERLAP`` is capped at whichever
            # of the two is shorter.
            #
            # ``GAPS`` is not touched here at all: it is kept in
            # absolute sequence numbers, so revising ``isn``
            # downward above does not require shifting or
            # re-prefixing a single entry in it.
            OFFSET = ISN - PSN                     # index into info.payload where the overlap begins
            OVERLAP = min(len(RAW), LEN - OFFSET)  # length of the overlapping range
            merged, conflicts = self._merge_overlap(
                GAPS,
                bytes(RAW[:OVERLAP]), bytes(info.payload[OFFSET:OFFSET + OVERLAP]),
                ISN,
            )
            RAW[:OVERLAP] = merged
            fragment.conflict.extend(conflicts)
            RAW = info.payload[:OFFSET] + RAW + info.payload[OFFSET + OVERLAP:]
        self._trim_gaps(GAPS, PSN, PSN + info.len - 1)
        fragment.__update__(
            raw=RAW,       # update payload datagram
            len=len(RAW),  # update payload length
        )

    def _update_hole_descriptors(self, BUFID: 'BufferID', first: 'int', last: 'int') -> 'None':
        """Update the buffer-wide hole descriptor list per :rfc:`815`.

        Called only for a segment that carries payload (``info.len > 0``);
        a bare acknowledgement, SYN, FIN or RST fills no hole, and running
        one through this would split whichever hole contains it into two
        adjacent holes covering the very same octets, growing the list
        without bound on a long-lived connection.

        The end of the stream is not settled here: a FIN cuts the open-ended
        hole back afterwards, in :meth:`_close_hole_descriptors`, whether or
        not it carries payload.

        Arguments:
            BUFID: buffer identifier of the session this fragment belongs to
            first: unwrapped sequence number of the segment's first octet
            last: unwrapped sequence number of the segment's last octet

        """
        HDL = self._buffer[BUFID].hdl                          # HDL alias
        new_hdl = []  # type: list[HoleDescriptor]
        for hole in HDL:                                       # step one
            if first > hole.last or last < hole.first:         # steps two and three
                new_hdl.append(hole)
                continue
            # step four: this hole is (partly) filled and replaced by what of
            # it survives, on either side of the segment
            if first > hole.first:                             # step five
                new_hdl.append(HoleDescriptor(
                    first=hole.first,
                    last=first - 1,
                ))
            if last < hole.last:                               # step six
                new_hdl.append(HoleDescriptor(
                    first=last + 1,
                    last=hole.last
                ))
            # step seven: go on to the next hole, since one segment may span
            # several of them
        HDL[:] = new_hdl

    @staticmethod
    def _trim_gaps(gap: 'list[tuple[int, int]]', first: 'int', last: 'int') -> 'None':
        """Remove a received range from a fragment's gap list, in place.

        Only an entry lying outside :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment.raw`
        -- the range a split stream left out, see :attr:`TCP.__window__` -- can
        still overlap a segment once it is merged; :meth:`_merge_overlap` has
        already closed every entry inside ``raw`` that the segment covers.

        Arguments:
            gap: the fragment's gap list
            first: unwrapped sequence number of the segment's first octet
            last: unwrapped sequence number of the segment's last octet

        """
        if first > last:
            return
        still_gap = []  # type: list[tuple[int, int]]
        for (lo, hi) in gap:
            if hi < first or lo > last:
                still_gap.append((lo, hi))
                continue
            if lo < first:
                still_gap.append((lo, first - 1))
            if hi > last:
                still_gap.append((last + 1, hi))
        gap[:] = still_gap

    @staticmethod
    def _merge_overlap(gap: 'list[tuple[int, int]]', old: 'bytes', new: 'bytes',
                        start: 'int') -> 'tuple[bytes, list[tuple[int, int]]]':
        """Merge an arriving segment into an overlapping range of buffered bytes.

        Arguments:
            gap: this *fragment's own*
                :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment.gap`
                list -- absolute, inclusive sequence ranges still zero-fill
                placeholder in ``old``. **Mutated in place**: whichever
                portion of a gap entry falls inside ``[start, start +
                len(old) - 1]`` is filled from ``new`` and removed (or
                trimmed, if only part of the entry falls inside the range).
                Deliberately **not** derived from
                :attr:`~pcapkit.foundation.reassembly.data.tcp.Buffer.hdl`,
                which is shared across every acknowledgement number under the
                same buffer ID: a *different* fragment closing a hole there
                says nothing about what *this* fragment has received, and
                using it here would discard this fragment's own real
                bytes whenever another fragment happened to cover the same
                absolute sequence numbers first.
            old: already-buffered bytes of this fragment over the range.
            new: the arriving segment's bytes over the same range.
            start: absolute sequence number of ``old[0]``/``new[0]``, which
                cover the same range by construction -- see the two call
                sites, :meth:`_reassemble_append` and :meth:`_reassemble_prepend`.

        Returns:
            The bytes to keep for the range, and any ``(first, last)``
            absolute sequence ranges -- inclusive, same convention as
            :attr:`gap` and :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment.conflict`
            -- where already-*received* bytes disagreed with the arriving
            segment.

        A position still covered by a ``gap`` entry has no already-received
        byte to disagree with, so the arriving segment's byte is simply
        accepted there and that slice of the gap is closed: an ordinary gap
        fill, not a conflict. Only a position outside every gap -- already
        received -- can conflict, per :rfc:`9293#section-3.10`: the
        already-received byte wins and the arriving one is discarded, but the
        disagreement itself is what this records for :attr:`Fragment.conflict
        <pcapkit.foundation.reassembly.data.tcp.Fragment.conflict>`.

        """
        length = len(old)
        end = start + length - 1                # inclusive
        merged = bytearray(old)

        # A position is a hole exactly while some gap entry covers it; build
        # that once, per this call, from the compact interval list rather
        # than keeping a per-octet marker between calls. Any gap entry (or
        # remaining slice of one) outside ``[start, end]`` is untouched.
        received = bytearray(b'\x01' * length)  # scratch for this call only
        still_gap = []  # type: list[tuple[int, int]]
        for (first, last) in gap:
            lo, hi = max(first, start), min(last, end)
            if lo > hi:             # this entry misses the range entirely
                still_gap.append((first, last))
                continue
            rel_lo, rel_hi = lo - start, hi - start         # inclusive
            merged[rel_lo:rel_hi + 1] = new[rel_lo:rel_hi + 1]
            received[rel_lo:rel_hi + 1] = bytes(rel_hi - rel_lo + 1)
            if first < lo:          # a leading slice of the entry survives
                still_gap.append((first, lo - 1))
            if last > hi:           # a trailing slice of the entry survives
                still_gap.append((hi + 1, last))
        gap[:] = still_gap

        conflicts = []  # type: list[tuple[int, int]]
        index = 0
        while index < length:
            if not received[index] or old[index] == new[index]:
                index += 1
                continue
            stop = index
            while stop < length and received[stop] and old[stop] != new[stop]:
                stop += 1
            conflicts.append((start + index, start + stop - 1))
            index = stop
        return bytes(merged), conflicts

    def submit(self, buf: 'Buffer', *, bufid: 'BufferID',  # type: ignore[override] # pylint: disable=arguments-differ
               timeout: 'bool' = False) -> 'list[Datagram]':
        """Submit reassembled payload.

        Arguments:
            buf: :term:`buffer <reasm.tcp.buffer>` dict of reassembled packets
            bufid: buffer identifier
            timeout: whether this buffer is being submitted because
                :meth:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase.expire`
                abandoned it under the reassembly timeout

        Returns:
            Reassembled :term:`packets <reasm.tcp.datagram>`.

        """
        datagram = []  # type: list[Datagram] # reassembled datagram

        # check through every buffer with ACK
        for (ack, buffer) in buf.ack.items():
            # Translate this payload buffer's own gap list, kept in unwrapped
            # sequence numbers, into offsets into the buffer, which is indexed
            # from its own initial sequence number. The buffer-wide hole
            # descriptor list cannot answer this: it is shared by every
            # acknowledgement number, so another payload buffer filling a hole
            # there says nothing about this one, and it never learns of a gap
            # opened below the first segment to arrive. Entries are clipped to
            # the buffer rather than being allowed to index from its far end.
            length = len(buffer.raw)
            holes = []  # type: list[tuple[int, int]]
            for (first, last) in buffer.gap:
                start = first - buffer.isn            # inclusive lower bound
                stop = last - buffer.isn + 1          # exclusive upper bound
                if stop <= 0 or start >= length:
                    continue                          # gap lies outside the buffer
                holes.append((max(start, 0), min(stop, length)))
            holes.sort()
            # reported in sequence space proper, i.e. modulo 2**32
            conflict = tuple((first & 0xFFFFFFFF, last & 0xFFFFFFFF)
                             for (first, last) in buffer.conflict)

            # How completely this buffer came out, and why it stopped. Derived
            # once per buffer, so the two branches cannot disagree about it.
            # Any gap entry counts, including one lying wholly outside ``raw``:
            # that is the range a split stream left out (see ``__window__``).
            completion = Completion.COMPLETE if not buffer.gap else (
                Completion.TIMEOUT if timeout else Completion.PARTIAL
            )

            # if this buffer is not implemented
            # go through every hole and extract received payload
            if completion is not Completion.COMPLETE and self._flag_s:
                data = []  # type: list[bytes]
                start = 0
                for (hole_start, hole_stop) in holes:
                    byte = buffer.raw[start:hole_start]
                    if byte:    # strip empty payload
                        data.append(bytes(byte))
                    start = max(start, hole_stop)
                byte = buffer.raw[start:]
                if byte:    # strip empty payload
                    data.append(bytes(byte))
                if data:    # strip empty buffer
                    packet = Datagram(
                        completed=completion,
                        id=DatagramID(
                            src=(bufid[0], bufid[1]),
                            dst=(bufid[2], bufid[3]),
                            ack=ack,
                        ),
                        index=tuple(buffer.ind),
                        header=buf.hdr,
                        payload=tuple(data),
                        packet=None,
                        conflict=conflict,
                    )
                    datagram.append(packet)

            # if this buffer is implemented -- or if it is not, and ``strict``
            # asked for one contiguous payload rather than the received runs
            #
            # NOTE: ``strict=False`` deliberately keeps reporting the whole
            # payload buffer with its holes zero-filled, which is what
            # :func:`~pcapkit.interface.misc.follow_tcp_stream` wants of a stream
            # it is reconstructing best-effort. ``completed`` says so, rather than
            # reporting :attr:`Completion.COMPLETE` for a buffer with holes in it.
            else:
                payload = buffer.raw
                if payload:    # strip empty buffer
                    packet = Datagram(
                        completed=completion,
                        id=DatagramID(
                            src=(bufid[0], bufid[1]),
                            dst=(bufid[2], bufid[3]),
                            ack=ack,
                        ),
                        index=tuple(buffer.ind),
                        header=buf.hdr,
                        payload=bytes(payload),
                        packet=Deferred(self.protocol.analyze, (bufid[1], bufid[3]), bytes(payload)),
                        conflict=conflict,
                    )
                    datagram.append(packet)

        for callback in self.__callback_fn__:
            callback(datagram)
        return datagram
