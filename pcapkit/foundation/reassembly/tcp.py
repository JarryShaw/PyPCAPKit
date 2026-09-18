# -*- coding: utf-8 -*-
"""TCP Datagram Reassembly
=============================

.. module:: pcapkit.foundation.reassembly.tcp

:mod:`pcapkit.foundation.reassembly.tcp` contains
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` only,
which reconstructs fragmented TCP packets back to origin.

"""
import math
import sys
from typing import TYPE_CHECKING

from pcapkit.foundation.reassembly.data.data import Completion, Deferred
from pcapkit.foundation.reassembly.data.tcp import (Buffer, BufferID, Datagram, DatagramID,
                                                    Fragment, HoleDescriptor, Packet)
from pcapkit.foundation.reassembly.reassembly import ReassemblyBase as Reassembly
from pcapkit.protocols.transport.tcp import TCP as TCP_Protocol

if TYPE_CHECKING:
    from typing import Type

__all__ = ['TCP']


class TCP(Reassembly[Packet, Datagram, BufferID, Buffer]):
    """Reassembly for TCP payload.

    Args:
        strict: if return all datagrams (including those not
                implemented) when submit
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
        matters. The :term:`hole descriptor list <reasm.tcp.buffer>` of
        :rfc:`815` is kept in **absolute TCP sequence numbers**, inclusive of
        both bounds, because a hole belongs to the connection's sequence space
        for that direction and not to any one payload buffer: the list is held
        once per buffer ID, while each acknowledgement number gets a payload
        buffer of its own with an initial sequence number of its own, and that
        initial sequence number is revised whenever a segment turns up below
        the data already buffered. A payload buffer, on the other hand, is
        indexed from zero, such that
        :attr:`buffer.raw[n] <pcapkit.foundation.reassembly.data.tcp.Fragment.raw>`
        holds the octet with sequence number
        :attr:`buffer.isn <pcapkit.foundation.reassembly.data.tcp.Fragment.isn>`
        ``+ n``. :meth:`submit` is therefore the one place that converts
        between the two, subtracting that buffer's initial sequence number from
        each hole bound.

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

        # initialise buffer with BUFID & ACK
        if BUFID not in self._buffer:
            self._buffer[BUFID] = Buffer(
                hdl=[
                    HoleDescriptor(
                        # everything from the octet after this segment onwards
                        # is still missing -- in absolute sequence numbers, so
                        # that the bound stays valid for every payload buffer
                        # under this buffer ID
                        first=PSN + info.len,
                        last=sys.maxsize,
                    ),
                ],
                hdr=info.header if SYN else b'',
                ack={
                    ACK: Fragment(
                        ind=[
                            info.num,
                        ],
                        isn=PSN,
                        len=info.len,
                        raw=info.payload,
                        # this segment's own payload is, by definition, all real
                        received=bytearray(b'\x01' * info.len),
                        conflict=[],
                    ),
                },
                timestamp=TS,
            )
        else:
            # initialise buffer with ACK
            if ACK not in self._buffer[BUFID].ack:
                self._buffer[BUFID].ack[ACK] = Fragment(
                    ind=[
                        info.num,
                    ],
                    isn=PSN,
                    len=info.len,
                    raw=info.payload,
                    received=bytearray(b'\x01' * info.len),
                    conflict=[],
                )
            else:
                # put header into header buffer
                if SYN:  # pragma: no cover
                    self._buffer[BUFID].__update__(hdr=info.header)

                # append packet index
                self._buffer[BUFID].ack[ACK].ind.append(info.num)

                # record fragment payload
                ISN = self._buffer[BUFID].ack[ACK].isn        # Initial Sequence Number
                RAW = self._buffer[BUFID].ack[ACK].raw        # Raw Payload Data
                RCVD = self._buffer[BUFID].ack[ACK].received  # this fragment's own received mask
                if PSN >= ISN:  # if fragment goes after existing payload
                    LEN = self._buffer[BUFID].ack[ACK].len
                    GAP = PSN - (ISN + LEN)     # gap length between payloads
                    if GAP >= 0:    # if fragment goes after existing payload
                        RAW += bytearray(GAP) + info.payload
                        RCVD += bytearray(GAP) + bytearray(b'\x01' * info.len)
                    else:
                        # Fragment partially overlaps existing payload. Per
                        # :rfc:`9293#section-3.10` ("we reconstruct the segment
                        # to contain just the new data"), an already-*received*
                        # byte wins over a conflicting arriving one; only a
                        # position this *fragment* has not received yet (per
                        # ``RCVD``, not the buffer-wide ``HDL`` -- see
                        # :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment.received`)
                        # has nothing to disagree with, so the arriving byte
                        # is simply accepted there -- an ordinary gap fill,
                        # not a conflict.
                        OFFSET = PSN - ISN                     # index into RAW where the overlap begins
                        OVERLAP = min(info.len, LEN - OFFSET)  # length of the overlapping range
                        merged, merged_rcvd, conflicts = self._merge_overlap(
                            bytes(RCVD[OFFSET:OFFSET + OVERLAP]),
                            bytes(RAW[OFFSET:OFFSET + OVERLAP]), bytes(info.payload[:OVERLAP]),
                            PSN,
                        )
                        RAW[OFFSET:OFFSET + OVERLAP] = merged
                        RCVD[OFFSET:OFFSET + OVERLAP] = merged_rcvd
                        self._buffer[BUFID].ack[ACK].conflict.extend(conflicts)
                        if info.len > OVERLAP:  # fragment reaches past the buffered end
                            RAW += info.payload[OVERLAP:]
                            RCVD += bytearray(b'\x01' * (info.len - OVERLAP))
                else:           # if fragment exceeds existing payload
                    LEN = info.len
                    GAP = ISN - (PSN + LEN)     # gap length between payloads
                    self._buffer[BUFID].ack[ACK].__update__(
                        isn=PSN,
                    )
                    if GAP >= 0:    # if fragment exceeds existing payload
                        RAW = info.payload + bytearray(GAP) + RAW
                        RCVD = bytearray(b'\x01' * info.len) + bytearray(GAP) + RCVD
                    else:
                        # Mirrored reach-back case: the fragment starts before
                        # ``ISN`` and its tail overlaps the start of the
                        # already-buffered payload. Same resolution -- keep
                        # already-received bytes, fill any hole among them from
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
                        OFFSET = ISN - PSN                     # index into info.payload where the overlap begins
                        OVERLAP = min(len(RAW), LEN - OFFSET)  # length of the overlapping range
                        merged, merged_rcvd, conflicts = self._merge_overlap(
                            bytes(RCVD[:OVERLAP]),
                            bytes(RAW[:OVERLAP]), bytes(info.payload[OFFSET:OFFSET + OVERLAP]),
                            ISN,
                        )
                        RAW[:OVERLAP] = merged
                        RCVD[:OVERLAP] = merged_rcvd
                        self._buffer[BUFID].ack[ACK].conflict.extend(conflicts)
                        RAW = info.payload[:OFFSET] + RAW + info.payload[OFFSET + OVERLAP:]
                        RCVD = (bytearray(b'\x01' * OFFSET) + RCVD
                                + bytearray(b'\x01' * (info.len - OFFSET - OVERLAP)))
                #self._buffer[BUFID].ack[ACK].raw = RAW       # update payload datagram
                #self._buffer[BUFID].ack[ACK].len = len(RAW)  # update payload length
                self._buffer[BUFID].ack[ACK].__update__(
                    raw=RAW,           # update payload datagram
                    received=RCVD,     # update this fragment's own received mask
                    len=len(RAW),      # update payload length
                )

            # update hole descriptor list
            #
            # A segment carrying no payload -- a bare acknowledgement, SYN, FIN
            # or RST -- fills no hole, so it must not be run through the
            # :rfc:`815` algorithm: its ``last`` lies one below its ``first``,
            # and letting that through would split whichever hole contains it
            # into two adjacent holes covering the very same octets, growing
            # the list without bound on a long-lived connection.
            if info.len > 0:
                HDL = self._buffer[BUFID].hdl                          # HDL alias
                for (index, hole) in enumerate(HDL):                   # step one
                    if info.first > hole.last:                         # step two
                        continue
                    if info.last < hole.first:                         # step three
                        continue
                    del HDL[index]                                     # step four
                    if info.first > hole.first:                        # step five
                        new_hole = HoleDescriptor(
                            first=hole.first,
                            last=info.first - 1,
                        )
                        HDL.insert(index, new_hole)
                        index += 1
                    if info.last < hole.last and not FIN and not RST:  # step six
                        new_hole = HoleDescriptor(
                            first=info.last + 1,
                            last=hole.last
                        )
                        HDL.insert(index, new_hole)
                    break                                              # step seven
                #self._buffer[BUFID].hdl = HDL                         # update HDL

        # when FIN/RST is set, submit buffer of this session
        if FIN or RST:
            self._dtgram.extend(
                self.submit(self._buffer.pop(BUFID), bufid=BUFID)
            )

    @staticmethod
    def _merge_overlap(rcvd: 'bytes', old: 'bytes', new: 'bytes',
                        start: 'int') -> 'tuple[bytes, bytes, list[tuple[int, int]]]':
        """Merge an arriving segment into an overlapping range of buffered bytes.

        Arguments:
            rcvd: this *fragment's own*
                :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment.received`
                mask over the range, ``1`` where ``old`` is a genuinely
                received byte of this fragment and ``0`` where it is still
                zero-fill placeholder for a gap this fragment itself has not
                received yet. Deliberately **not** derived from
                :attr:`~pcapkit.foundation.reassembly.data.tcp.Buffer.hdl`,
                which is shared across every acknowledgement number under the
                same buffer ID: a *different* fragment closing a hole there
                says nothing about what *this* fragment has received, and
                using it here previously discarded this fragment's own real
                bytes whenever another fragment happened to cover the same
                absolute sequence numbers first.
            old: already-buffered bytes of this fragment over the range.
            new: the arriving segment's bytes over the same range.
            start: absolute sequence number of ``old[0]``/``new[0]``/``rcvd[0]``,
                which all cover the same range by construction -- see the two
                call sites in :meth:`reassembly`.

        Returns:
            The bytes to keep for the range, the updated ``received`` mask
            for the same range, and any ``(first, last)`` absolute sequence
            ranges -- inclusive, same convention as
            :class:`~pcapkit.foundation.reassembly.data.tcp.HoleDescriptor`
            -- where already-*received* bytes disagreed with the arriving
            segment.

        A position this fragment has not received yet has no already-received
        byte to disagree with, so the arriving segment's byte is simply
        accepted there and the mask is updated to say so: an ordinary gap
        fill, not a conflict. Only a position this fragment has already
        received can conflict, per :rfc:`9293#section-3.10`: the
        already-received byte wins and the arriving one is discarded, but the
        disagreement itself is what this records for :attr:`Fragment.conflict
        <pcapkit.foundation.reassembly.data.tcp.Fragment.conflict>`.

        """
        length = len(old)
        merged = bytearray(old)
        received = bytearray(rcvd)
        conflicts = []  # type: list[tuple[int, int]]
        index = 0
        while index < length:
            if not received[index]:    # this fragment has not received this byte yet
                merged[index] = new[index]
                received[index] = 1
                index += 1
                continue
            if old[index] == new[index]:
                index += 1
                continue
            stop = index
            while stop < length and received[stop] and old[stop] != new[stop]:
                stop += 1
            conflicts.append((start + index, start + stop - 1))
            index = stop
        return bytes(merged), bytes(received), conflicts

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
        HDL = buf.hdl                         # hole descriptor list

        # check through every buffer with ACK
        for (ack, buffer) in buf.ack.items():
            # Translate the hole descriptor list, which is kept in absolute
            # sequence numbers for the whole direction, into offsets into this
            # payload buffer, which is indexed from its own initial sequence
            # number. Holes lying wholly outside this buffer -- the open-ended
            # one past the last octet received, and any belonging to a
            # different acknowledgement number's data -- drop out here; those
            # straddling an edge are clipped to it rather than being allowed to
            # index from the far end of the buffer as a negative bound would.
            length = len(buffer.raw)
            holes = []  # type: list[tuple[int, int]]
            for hole in HDL:
                start = hole.first - buffer.isn       # inclusive lower bound
                stop = hole.last - buffer.isn + 1     # exclusive upper bound
                if stop <= 0 or start >= length:
                    continue                          # hole misses this buffer
                holes.append((max(start, 0), min(stop, length)))
            holes.sort()

            # How completely this buffer came out, and why it stopped. Derived
            # once per buffer, so the two branches cannot disagree about it.
            completion = Completion.COMPLETE if not holes else (
                Completion.TIMEOUT if timeout else Completion.PARTIAL
            )

            # if this buffer is not implemented
            # go through every hole and extract received payload
            if holes and self._flag_s:
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
                        conflict=tuple(buffer.conflict),
                    )
                    datagram.append(packet)

            # if this buffer is implemented -- or if it is not, and ``strict``
            # asked for one contiguous payload rather than the received runs
            #
            # NOTE: ``strict=False`` deliberately keeps reporting the whole
            # payload buffer with its holes zero-filled, which is what
            # :func:`~pcapkit.interface.misc.follow_tcp_stream` wants of a stream
            # it is reconstructing best-effort. What changes is only that
            # ``completed`` now says so: this branch used to report
            # :attr:`Completion.COMPLETE` for a buffer it knew had holes in it.
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
                        conflict=tuple(buffer.conflict),
                    )
                    datagram.append(packet)

        for callback in self.__callback_fn__:
            callback(datagram)
        return datagram
