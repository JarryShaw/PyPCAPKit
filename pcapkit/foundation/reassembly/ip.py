# -*- coding: utf-8 -*-
"""IP Datagram Reassembly
============================

.. module:: pcapkit.foundation.reassembly.ip

:mod:`pcapkit.foundation.reassembly.ip` contains
:class:`~pcapkit.foundation.reassembly.ip.IP`
only, which reconstructs fragmented IP packets back to
origin. The implementation follows the IP reassembly
procedure introduced in :rfc:`791`, using ``RCVBT``
(fragment received bit table). :rfc:`815` explains another
algorithm, replacing ``RCVBT``, but this implementation
uses the elder one.

"""
import bisect
import sys
from functools import partial
from typing import TYPE_CHECKING, Generic

from pcapkit.foundation.analysis.ip import _analyze_payload
from pcapkit.foundation.reassembly.data.data import Completion
from pcapkit.foundation.reassembly.data.ip import (_AT, Buffer, BufferID, Datagram, DatagramID,
                                                   Deferred, Packet)
from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
from pcapkit.protocols.schema.internet.ipv6 import IP_MAX_LENGTH
from pcapkit.utilities.logging import get_logger

if TYPE_CHECKING:
    from typing import Optional, Type

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.protocols.internet.ip import IP as IP_Protocol

__all__ = ['IP']

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


class IP(ReassemblyBase[Packet[_AT], Datagram[_AT], BufferID, Buffer[_AT]], Generic[_AT]):  # pylint: disable=abstract-method
    """Reassembly for IP payload.

    Args:
        strict: if :data:`True`, report a datagram that is not completely
            reassembled as the tuple of its received runs, empty if none was;
            otherwise as one contiguous payload, its holes zero-filled -- or,
            while the total length is unknown, only the prefix up to the first
            hole. Receipt is tracked in 8-octet blocks, and only the final
            fragment's partial last block counts as received -- a non-final
            fragment's, or a snaplen-truncated or buffer-clipped fragment's,
            does not: it is left out of the runs and ends the prefix, but once
            the total length is known the contiguous payload keeps its real
            octets, with only the rest of the hole zero-filled. A datagram
            longer than its length field can declare is never complete
        store: if store reassembled datagram in memory, i.e.,
            :attr:`self._dtgram <pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram>`
            (if not, datagram will be discarded after callback)
        timeout: reassembly timeout in seconds, on the capture's own clock;
            :data:`None` selects the protocol's
            :attr:`__timeout__ <pcapkit.foundation.reassembly.reassembly.Reassembly.__timeout__>`
            default

    Important:
        This class is not intended to be instantiated directly,
        but rather used as a base class for the protocol-aware
        reassembly classes.

    .. versionchanged:: 1.5.0

       An overlapping fragment that disagrees with octets already received
       overwrites them, as :rfc:`791` asks, and the disagreement is recorded in
       :attr:`Datagram.conflict
       <pcapkit.foundation.reassembly.data.ip.Datagram.conflict>`
       (:issue:`477`). An incomplete buffer expires
       after ``timeout`` seconds of capture time, 60 by default for both IPv4
       and IPv6. A datagram with fragment offset zero and **MF** (**M** in
       IPv6) clear is reported even when its BUFID is already buffered,
       rather than dropped (:issue:`2270`).

    .. versionchanged:: 1.6.0

       A subclass setting :attr:`__discard_overlap__` abandons a datagram on an
       overlapping fragment instead of overwriting, and
       :class:`~pcapkit.foundation.reassembly.ipv6.IPv6` does (:issue:`2547`).

    """
    if TYPE_CHECKING:
        protocol: 'Type[IP_Protocol]'

    #: bool: Whether a datagram with fragment offset zero and **MF** clear is
    #: reassembled apart from the buffer its BUFID names, rather than flushing
    #: that buffer first. IPv4 flushes it (:rfc:`791#section-3.2`); IPv6
    #: overrides this, since :rfc:`6946#section-4` keeps an atomic fragment's
    #: buffer intact (:issue:`2270`).
    __isolate_atomic__: 'bool' = False

    #: bool: Whether a fragment overlapping another of its datagram abandons
    #: that datagram, reported as
    #: :attr:`Completion.OVERLAP <pcapkit.foundation.reassembly.data.data.Completion.OVERLAP>`,
    #: rather than overwriting the octets it overlaps. IPv4 overwrites them
    #: (:rfc:`791#section-3.2`); IPv6 overrides this, since
    #: :rfc:`8200#section-4.5` discards the datagram (:issue:`2547`).
    #:
    #: .. versionadded:: 1.6.0
    __discard_overlap__: 'bool' = False

    ##########################################################################
    # Methods.
    ##########################################################################

    def _rectify_header(self, header: 'bytes', proto: 'TransType') -> 'bytes':  # pylint: disable=unused-argument
        """Adapt a fragment's header into the reassembled datagram's header.

        The base implementation returns ``header`` unchanged, which is what IPv4
        wants: an IPv4 fragment's header needs nothing removed to describe the
        datagram it belongs to. IPv6 overrides this, because
        :rfc:`8200#section-4.5` drops the Fragment header from the reassembled
        packet and hands its Next Header field to the header before it.

        Args:
            header: Raw header octets of the fragment at fragment offset zero.
            proto: Payload protocol type, i.e. ``bufid[3]``.

        Returns:
            Header octets to keep for the reassembled datagram.

        """
        return header

    def _header_overhead(self, length: 'int') -> 'int':
        """Count the header octets that a datagram's length field includes.

        The base implementation counts them all, which is what IPv4 wants: its
        Total Length is the header's length plus the data's
        (:rfc:`791#section-3.1`). IPv6 overrides this, because its Payload
        Length leaves out the fixed header (:rfc:`8200#section-3`).

        Args:
            length: Length of the datagram's header.

        Returns:
            How many of those octets the length field counts.

        """
        return length

    def reassembly(self, info: 'Packet[_AT]') -> 'None':
        """Reassembly procedure.

        Arguments:
            info: :term:`info` record of packets to be reassembled

        Note:
            A completed datagram's buffer is freed, as in the
            :rfc:`791#section-3.2` reassembly procedure, so a fragment of it
            that arrives afterwards -- a late duplicate, say -- opens a new
            buffer. The caller sees that buffer as a separate incomplete
            datagram, ``PARTIAL`` at the end of the capture or ``TIMEOUT`` if
            it expires first. This is intended, is permitted by
            :rfc:`8200#section-4.5`, and matches Linux, Zeek and Wireshark
            (:issue:`1507`).

        """
        # clear cache
        self._flag_n = False
        self.__cached__.clear()

        BUFID = info.bufid   # Buffer Identifier
        FO = info.fo         # Fragment Offset
        IHL = info.ihl       # Internet Header Length
        MF = info.mf         # More Fragments flag
        TL = info.tl         # Total Length
        TS = info.timestamp  # Capture timestamp, i.e. the only clock we have

        # This fragment's arrival is the evidence that capture time has reached
        # ``TS``, so it is the moment to abandon whatever the deadline has now
        # passed for -- including, deliberately, buffers this fragment does not
        # belong to.
        self._dtgram.extend(self.expire(TS))

        # a datagram with fragment offset zero and MF clear is reported even
        # when its BUFID is already buffered, rather than dropped: isolated
        # from that buffer (IPv6 atomic fragments) or after flushing it first
        # (IPv4) (#2270)
        isolated = False
        if not FO and not MF:
            if self.__isolate_atomic__:
                # an IPv6 atomic fragment "MUST" be processed in isolation, and
                # fragments queued under its BUFID "MUST NOT" be discarded
                # (:rfc:`6946#section-4`), so the buffer is left alone
                isolated = True
            elif BUFID in self._buffer:
                # :rfc:`791#section-3.2` flushes the buffer and then submits
                # this datagram, so the flushed one is reported incomplete and
                # this one goes on to a fresh buffer below
                self._dtgram.extend(
                    self.submit(self._buffer.pop(BUFID), bufid=BUFID)
                )

        # the header of the fragment at offset zero is the reassembled datagram's
        header = b'' if FO else self._rectify_header(info.header, BUFID[3])

        # initialise buffer with BUFID; ``RCVBT`` holds one entry per 8-octet
        # block of the data buffer, its partial last block included -- 8191
        # would cover octets 0 to 65527 only, so a fragment reaching octet 65528,
        # e.g. at the largest Fragment Offset, would index past it (#1565)
        buf: 'Buffer[_AT]'
        fresh = isolated or BUFID not in self._buffer
        if fresh:
            buf = Buffer(
                TDL=-1,                              # Total Data Length
                RCVBT=bytearray(8192),              # Fragment Received Bit Table
                index=[],                           # index record
                header=header,                      # header buffer
                datagram=bytearray(IP_MAX_LENGTH),  # data buffer
                timestamp=TS,                       # first-arriving fragment's clock reading
                conflict=[],                        # conflicting octet ranges
                extent=[],                          # merged fragments' extents
            )
            if not isolated:
                self._buffer[BUFID] = buf
        else:
            buf = self._buffer[BUFID]

        # append packet index
        buf.index.append(info.num)

        # The fragment's data length is what its header declares, but only the
        # octets the capture actually holds can be written: a snaplen-truncated
        # fragment carries fewer, and anything past the declared length is not
        # fragment data. The data buffer is preallocated, so the write is also
        # clipped to it.
        #
        # A Total Length of 0 declares nothing. It is what TCP segmentation
        # offload leaves in a capture taken on the sending host, and the
        # datagram then runs to the end of the captured frame (#1547).
        # Wireshark ("presumed TSO") substitutes that length for the field
        # before it reassembles anything, and so does this, whatever **MF** and
        # the offset say: an unfragmented one is then whole rather than ``-IHL``
        # octets long (#1555). Linux's BIG TCP zeroes the field
        # precisely because the datagram, header included, outgrows the 65535
        # octets it can declare -- and such a datagram never completes in a
        # buffer of that length (:meth:`_is_complete`). So the buffer grows past
        # it, to hold the datagram rather than clip it, ``RCVBT`` in step with
        # it; it grows by an octet even when the data alone would fit, since its
        # growing is what lifts the bound.
        #
        # With nothing declared, a snaplen cut cannot be seen in the length. A
        # non-final fragment's cut still shows, as a partial last block, which
        # is left unmarked below. Any other cut -- an unfragmented frame's, or
        # a final fragment's -- cannot be told from a whole one, since the
        # frame's original length is not part of the input, and the datagram
        # comes out ``COMPLETE`` but short.
        if TL == 0:
            length = len(info.payload)
            extent = FO + length
            if self._header_overhead(IHL) + extent > IP_MAX_LENGTH:
                size = max(extent, IP_MAX_LENGTH + 1, len(buf.datagram))
                buf.datagram.extend(bytes(size - len(buf.datagram)))
                buf.RCVBT.extend(bytes((size + 7) // 8 - len(buf.RCVBT)))
        else:
            length = TL - IHL
        held = max(min(len(info.payload), length, len(buf.datagram) - FO), 0)
        payload = info.payload[:held]

        # put data into data buffer
        start = FO
        stop = FO + held

        # Find where this fragment disagrees with what the buffer already
        # holds *before* writing it -- ``buf.RCVBT`` and ``buf.TDL`` still
        # describe the state as every earlier fragment left it, which is
        # exactly what :meth:`_detect_conflicts` needs.
        conflicts = self._detect_conflicts(buf.RCVBT, buf.TDL, buf.datagram, payload, start, stop)
        if conflicts:
            buf.conflict.extend(conflicts)

        # :rfc:`8200#section-4.5` abandons a datagram, and discards every
        # fragment received for it, once one fragment overlaps another; it lets
        # an implementation drop an exact duplicate instead, which this does.
        # The span is the length the fragment declares, not the octets it
        # holds. A fresh buffer has no extent to overlap, so the ``pop`` below
        # never reaches an isolated one.
        if self.__discard_overlap__:
            span = (FO, FO + max(length, 0), MF)
            other = self._find_overlap(buf.extent, span[0], span[1])
            if other is not None:
                if other == span and buf.datagram[start:stop] == payload:
                    return
                logger.debug('%s: abandoning buffer %s on frame %d, which overlaps '
                             'octets %d-%d', self.name, BUFID, info.num, other[0], other[1] - 1)
                self._dtgram.extend(
                    self.submit(self._buffer.pop(BUFID), bufid=BUFID, overlap=True)
                )
                return
            if span[1] > span[0]:
                bisect.insort(buf.extent, span)

        # put header into header buffer, once the fragment is known to be kept
        if not FO and not fresh:
            buf.__update__(header=header)

        # :rfc:`791` is explicit that an overlapping fragment's data "will use
        # the more recently arrived copy in the data buffer" -- the opposite of
        # TCP's first-write-wins (:rfc:`9293#section-3.10`) -- so the arriving
        # payload always overwrites here; ``conflicts`` above is what records
        # that it *disagreed* with what it overwrote, which is the part RFC 791
        # leaves unrecorded.
        buf.datagram[start:stop] = payload

        # Set RCVBT bits (in 8 octets) for the blocks this fragment actually
        # filled. Only the final fragment, held in full, marks a partial last
        # block: the octets after its end are past the datagram's. Every other
        # partial last block is left clear, as a hole --
        #
        # * a truncated fragment's, since the octets after the cut are missing.
        #   That includes one clipped by the data buffer's end, whose octets
        #   past it cannot be held, so it counts as cut there (#1566).
        # * a non-final fragment's. :rfc:`791#section-3.2` and
        #   :rfc:`8200#section-4.5` make every fragment but the last carry a
        #   multiple of 8 octets, so one that ends mid-block was cut or is
        #   malformed, and nobody sent the rest of its block. Marking it would
        #   complete the datagram with zeros in their place. This is the only
        #   way a cut shows when the length is not declared: under Total
        #   Length 0, and on IPv6, whose adapters derive it from the captured
        #   payload (#1567).
        start = FO // 8
        if held == length and not MF:
            stop = (FO + held + 7) // 8
        else:
            stop = (FO + held) // 8
        stop = min(stop, len(buf.RCVBT))
        if stop > start:
            buf.RCVBT[start:stop] = b'\x01' * (stop - start)

        # get total data length (header excludes); it stays ``-1`` until the
        # fragment with MF clear has arrived, and ``0`` is a valid length
        if not MF:
            buf.__update__(TDL=length + FO)

        # an isolated datagram has no buffer to wait in, so it is submitted
        # whether or not it is complete
        if isolated:
            self._dtgram.extend(self.submit(buf, bufid=BUFID))
        # when datagram is reassembled in whole
        elif self._is_complete(buf):
            self._dtgram.extend(
                self.submit(self._buffer.pop(BUFID), bufid=BUFID, checked=True)
            )

    def _is_complete(self, buf: 'Buffer[_AT]') -> 'bool':
        """Tell whether a buffer holds its whole datagram.

        Arguments:
            buf: buffer to check

        Returns:
            Whether the total data length is known, the datagram is no longer
            than it may be, and every 8-octet block up to it is marked
            received.

        A datagram is no longer than
        :data:`~pcapkit.protocols.schema.internet.ipv6.IP_MAX_LENGTH` with its header, as
        :meth:`_header_overhead` counts it: IPv4's Total Length counts the
        whole header, and IPv6's Payload Length every header but the fixed one.
        A longer datagram cannot be declared, so it is never complete, and
        Linux's ``ip_frag_reasm`` and ``ip6_frag_reasm`` reject it too
        (:issue:`1585`). A fragment with Total Length 0 declares no length, so
        a buffer it has grown past that bounds the datagram by its own length
        alone (:issue:`1555`). Checking ``RCVBT`` does not show either bound:
        slicing it past its end stops silently, so the blocks past the buffer
        would read as received (:issue:`1566`).

        """
        TDL = buf.TDL
        if len(buf.datagram) > IP_MAX_LENGTH:
            limit = len(buf.datagram)
        else:
            limit = IP_MAX_LENGTH - self._header_overhead(len(buf.header))
        return 0 <= TDL <= limit and all(buf.RCVBT[:(TDL + 7) // 8])

    @staticmethod
    def _detect_conflicts(rcvbt: 'bytearray', tdl: 'int', datagram: 'bytearray', payload: 'bytearray',
                           start: 'int', stop: 'int') -> 'list[tuple[int, int]]':
        """Find where an arriving fragment disagrees with already-received bytes.

        Arguments:
            rcvbt: this buffer's :attr:`~pcapkit.foundation.reassembly.data.ip.Buffer.RCVBT`
                as it stood *before* the arriving fragment's own bits are set,
                i.e. what earlier fragments had already claimed, in 8-octet
                blocks.
            tdl: this buffer's :attr:`~pcapkit.foundation.reassembly.data.ip.Buffer.TDL`
                as it stood *before* the arriving fragment's own update --
                ``-1`` while the final fragment (``MF=0``) has not yet
                arrived.
            datagram: this buffer's data buffer, read *before* the arriving
                fragment's payload is written into it.
            payload: the arriving fragment's payload.
            start: absolute octet offset of ``payload[0]`` in ``datagram``,
                i.e. this fragment's ``FO``.
            stop: absolute octet offset one past ``payload[-1]``, i.e.
                ``start + len(payload)``.

        Returns:
            ``(first, last)`` absolute octet ranges, inclusive, where
            ``datagram`` and ``payload`` disagree over octets this buffer had
            already genuinely received.

        :rfc:`791` marks receipt in 8-octet blocks (``RCVBT``), coarser than
        the octet granularity a conflict needs, so an octet is compared only if
        its block is marked. A fragment's ``FO`` is *always* a multiple of 8 --
        it is wire-encoded in 8-octet units -- and the ``RCVBT`` update in
        :meth:`reassembly` marks the blocks a fragment fills whole. Only the
        final fragment, held in full, also marks its partial last block, across
        its full 8 octets even though only the octets up to ``tdl`` were ever
        actually written, the rest still being ``datagram``'s zero-fill.

        So once ``tdl`` is known, an octet at or past it is excluded here
        regardless of its block's bit -- comparing it would manufacture a
        conflict against a byte nothing ever really sent, over a distinction
        :meth:`~pcapkit.foundation.reassembly.ip.IP.submit` does not need
        anyway, since it never reports a payload past ``tdl``. Before ``tdl``
        is known (``tdl < 0``), every set ``rcvbt`` bit came from a non-final
        fragment's whole block and is exact on its own, with nothing to clip.

        Any other partial last block -- a non-final, truncated or clipped
        fragment's -- is written but left clear (:issue:`1567`), so its octets
        are deliberately not compared: a later fragment that overwrites them
        records no conflict, whether or not it agrees (:issue:`1585`). Telling
        which octets of a clear block were written would take receipt state per
        octet, which ``RCVBT`` does not keep. Linux never compares a non-final
        fragment's partial block either: it trims an IPv4 one to a multiple of
        8 (``ip_frag_queue``) and drops an IPv6 one (``ip6_frag_queue``).

        """
        conflicts = []  # type: list[tuple[int, int]]
        length = stop - start
        index = 0
        while index < length:
            pos = start + index
            if not (rcvbt[pos // 8] and (tdl < 0 or pos < tdl)):
                index += 1
                continue
            if datagram[pos] == payload[index]:
                index += 1
                continue
            run_stop = index + 1
            while run_stop < length:
                pos = start + run_stop
                if not (rcvbt[pos // 8] and (tdl < 0 or pos < tdl)):
                    break
                if datagram[pos] == payload[run_stop]:
                    break
                run_stop += 1
            conflicts.append((start + index, start + run_stop - 1))
            index = run_stop
        return conflicts

    @staticmethod
    def _find_overlap(extent: 'list[tuple[int, int, bool]]', start: 'int',
                      stop: 'int') -> 'Optional[tuple[int, int, bool]]':
        """Find a merged fragment that an arriving one overlaps.

        Arguments:
            extent: this buffer's
                :attr:`~pcapkit.foundation.reassembly.data.ip.Buffer.extent`,
                sorted and pairwise disjoint.
            start: the arriving fragment's first octet, i.e. its ``FO``.
            stop: one past the arriving fragment's last octet.

        Returns:
            The extent of a merged fragment sharing an octet with the arriving
            one, or :data:`None` if none does.

        Since the extents are disjoint, only the last one starting at or before
        ``start`` and the first one starting after it can reach the arriving
        fragment.

        """
        if stop <= start:
            return None
        after = bisect.bisect_right(extent, (start, sys.maxsize, True))
        if after and extent[after - 1][1] > start:
            return extent[after - 1]
        if after < len(extent) and extent[after][0] < stop:
            return extent[after]
        return None

    def submit(self, buf: 'Buffer[_AT]', *, bufid: 'tuple[_AT, _AT, int, TransType]',  # type: ignore[override] # pylint: disable=arguments-differ
               checked: 'bool' = False, timeout: 'bool' = False,
               overlap: 'bool' = False) -> 'list[Datagram[_AT]]':
        """Submit reassembled payload.

        Arguments:
            buf: buffer dict of reassembled packets
            bufid: buffer identifier
            checked: buffer consistency checked flag
            timeout: whether this buffer is being submitted because
                :meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.expire`
                abandoned it under the reassembly timeout, which is what
                separates
                :attr:`Completion.TIMEOUT <pcapkit.foundation.reassembly.data.data.Completion.TIMEOUT>`
                from
                :attr:`Completion.PARTIAL <pcapkit.foundation.reassembly.data.data.Completion.PARTIAL>`
            overlap: whether this buffer is being submitted because an
                overlapping fragment abandoned it (:attr:`__discard_overlap__`),
                reported as :attr:`Completion.OVERLAP
                <pcapkit.foundation.reassembly.data.data.Completion.OVERLAP>`
                and never as complete

        Returns:
            Reassembled packets. Where the payload is one contiguous run, its
            ``packet`` is the parse
            :func:`~pcapkit.foundation.analysis.ip.ip_datagram` runs, by this
            reassembly's own
            :attr:`protocol <pcapkit.foundation.reassembly.reassembly.Reassembly.protocol>`,
            deferred to its first read.

        """
        TDL = buf.TDL
        RCVBT = buf.RCVBT
        index = buf.index
        header = buf.header
        datagram = buf.datagram
        conflict = tuple(buf.conflict)

        flag = not overlap and (checked or self._is_complete(buf))
        ret = []  # type: list[Datagram[_AT]]

        # How completely this datagram came out, and why it stopped. Derived once,
        # so the two branches below cannot disagree about it.
        completion = Completion.COMPLETE if flag else (
            Completion.OVERLAP if overlap else Completion.TIMEOUT if timeout else Completion.PARTIAL
        )

        # if datagram is incomplete
        if not flag and self._flag_s:
            data = []  # type: list[bytes]
            byte = bytearray()
            # extract received payload; a run never extends past the total
            # data length once it is known
            limit = TDL if TDL >= 0 else len(datagram)
            for (bctr, bit) in enumerate(RCVBT):
                if bit:     # received bit
                    this = bctr * 8
                    that = min(this + 8, limit)
                    byte += datagram[this:that]
                else:       # missing bit
                    if byte:    # strip empty payload
                        data.append(bytes(byte))
                    byte = bytearray()
            # the last run may reach the end of the bit table
            if byte:
                data.append(bytes(byte))
            # Report it even with no run received, its payload ``()``, as
            # ``strict=False`` reports it with an empty payload: ``index``
            # still says which frames were its fragments (#1566).
            packet = Datagram(
                completed=completion,
                id=DatagramID(
                    src=bufid[0],
                    dst=bufid[1],
                    id=bufid[2],
                    proto=bufid[3],
                ),
                index=tuple(index),
                header=header,
                payload=tuple(data),
                packet=None,
                conflict=conflict,
            )
            ret.append(packet)
        # if datagram is reassembled in whole -- or if it is not, and ``strict``
        # asked for one contiguous payload rather than the received runs
        else:
            # ``TDL`` is the datagram's total length, and it is only known once the
            # fragment with **MF** clear has arrived -- until then it is still its
            # initial ``-1``. Which case this is decides how much of the buffer
            # there is to report.
            if TDL >= 0:
                # The length is known. Report it, holes and all: the gaps read as
                # zeros, exactly as they do in the TCP reassembler's loose mode.
                # This is the reason ``strict=False`` exists -- a caller who
                # wants the gaps *marked* rather than
                # zero-filled uses ``strict=True`` and gets the runs. A truncated
                # fragment's partial last block is not marked received, but the
                # octets it did write are real and are reported here as they are.
                stop = TDL
            else:
                # The length is not known. Slicing ``datagram[:-1]`` here would
                # hand back 65534 octets of the preallocated buffer, almost all of
                # them zeros the sender never sent, and call the result complete.
                #
                # Reporting nothing at all would be the other extreme, and it
                # discards data that really did arrive. So report the **contiguous
                # prefix**: every octet from offset zero up to the first hole. That
                # is the longest run whose extent is known without knowing the
                # total length, it is all genuinely received, and it is the part a
                # caller asking for one contiguous payload can actually use --
                # a parser reading a payload from its start cannot use a run that
                # begins after an unmeasured gap anyway. Anything past the first
                # hole is still reported by ``strict=True``, which lists the runs
                # precisely because their offsets cannot be conveyed in a blob.
                #
                # ``RCVBT`` records receipt in 8-octet units, so the prefix ends at
                # the first clear bit -- which leaves out a truncated fragment's
                # partial last block, octets that the known-length case above
                # does report.
                received = 0
                for bit in RCVBT:
                    if not bit:
                        break
                    received += 1
                stop = received * 8
            payload = bytes(datagram[:stop])
            packet = Datagram(
                completed=completion,
                id=DatagramID(
                    src=bufid[0],
                    dst=bufid[1],
                    id=bufid[2],
                    proto=bufid[3],
                ),
                index=tuple(index),
                header=header,
                payload=payload,
                # NOTE: ``analyze`` is a second full parse of the payload, and an
                # IPv4 datagram is submitted for every frame with **DF** clear
                # rather than only for the fragmented ones, so running it here
                # charges every caller for a result most of them never read.
                # ``Deferred`` postpones it to the first read of
                # ``Datagram.packet``.
                packet=Deferred(partial(_analyze_payload, self.protocol), bufid[3], payload),
                conflict=conflict,
            )
            ret.append(packet)

        for callback in self.__callback_fn__:
            callback(ret)
        return ret
