# -*- coding: utf-8 -*-
"""IP Datagram Reassembly
============================

.. module:: pcapkit.foundation.reassembly.ip

:mod:`pcapkit.foundation.reassembly.ip` contains
:class:`~pcapkit.foundation.reassembly.ip.IP`
only, which reconstructs fragmented IP packets back to
origin. The following algorithm implement is based on IP
reassembly procedure introduced in :rfc:`791`, using
``RCVBT`` (fragment received bit table). Though another
algorithm is explained in :rfc:`815`, replacing ``RCVBT``,
however, this implement still used the elder one.

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.foundation.reassembly.data.data import Completion
from pcapkit.foundation.reassembly.data.ip import (_AT, Buffer, BufferID, Datagram, DatagramID,
                                                   Deferred, Packet)
from pcapkit.foundation.reassembly.reassembly import ReassemblyBase

if TYPE_CHECKING:
    from typing import Type

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.protocols.internet.ip import IP as IP_Protocol

__all__ = ['IP']


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
            longer than the data buffer is never complete
        store: if store reassembled datagram in memory, i.e.,
            :attr:`self._dtgram <pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram>`
            (if not, datagram will be discarded after callback)
        timeout: reassembly timeout in seconds, on the capture's own clock;
            :data:`None` selects the protocol's :attr:`__timeout__` default

    Important:
        This class is not intended to be instantiated directly,
        but rather used as a base class for the protocol-aware
        reassembly classes.

    """
    if TYPE_CHECKING:
        protocol: 'Type[IP_Protocol]'

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

    def reassembly(self, info: 'Packet[_AT]') -> 'None':
        """Reassembly procedure.

        Arguments:
            info: info dict of packets to be reassembled

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

        # when non-fragmented (possibly discarded) packet received
        if not FO and not MF:
            if BUFID in self._buffer:
                self._dtgram.extend(
                    self.submit(self._buffer.pop(BUFID), bufid=BUFID)
                )
                return

        # the header of the fragment at offset zero is the reassembled datagram's
        header = b'' if FO else self._rectify_header(info.header, BUFID[3])

        # initialise buffer with BUFID; ``RCVBT`` holds one entry per 8-octet
        # block of the data buffer, its partial last block included -- 8191
        # covered octets 0 to 65527 only, so a fragment reaching octet 65528,
        # e.g. at the largest Fragment Offset, indexed past it (:issue:`1565`)
        if BUFID not in self._buffer:
            self._buffer[BUFID] = Buffer(
                TDL=-1,                              # Total Data Length
                RCVBT=bytearray(8192),              # Fragment Received Bit Table
                index=[],                           # index record
                header=header,                      # header buffer
                datagram=bytearray(65535),          # data buffer
                timestamp=TS,                       # first-arriving fragment's clock reading
                conflict=[],                        # conflicting octet ranges
            )
        else:
            # put header into header buffer
            if not FO:  # pylint: disable=else-if-used
                self._buffer[BUFID].__update__(header=header)

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
        # datagram then runs to the end of the captured frame -- which is the
        # payload every adapter hands over (:issue:`1547`). Wireshark ("presumed
        # TSO") substitutes that length for the field before it reassembles
        # anything, and so does this, whatever **MF** and the offset say: an
        # unfragmented one is then whole rather than ``-IHL`` octets long
        # (:issue:`1555`). Linux's BIG TCP zeroes the field precisely because
        # the datagram outgrows the 65535 octets it can declare, so the buffer
        # grows to hold such a datagram rather than clipping it, ``RCVBT`` in
        # step with it.
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
            if extent > len(buf.datagram):
                buf.datagram.extend(bytes(extent - len(buf.datagram)))
                buf.RCVBT.extend(bytes((extent + 7) // 8 - len(buf.RCVBT)))
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
        #   past it cannot be held, so it counts as cut there (:issue:`1566`).
        # * a non-final fragment's. :rfc:`791#section-3.2` and
        #   :rfc:`8200#section-4.5` make every fragment but the last carry a
        #   multiple of 8 octets, so one that ends mid-block was cut or is
        #   malformed, and nobody sent the rest of its block. Marking it would
        #   complete the datagram with zeros in their place. This is the only
        #   way a cut shows when the length is not declared: under Total
        #   Length 0, and on IPv6, whose adapters derive it from the captured
        #   payload (:issue:`1567`).
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

        # when datagram is reassembled in whole
        if self._is_complete(buf):
            self._dtgram.extend(
                self.submit(self._buffer.pop(BUFID), bufid=BUFID, checked=True)
            )

    @staticmethod
    def _is_complete(buf: 'Buffer[_AT]') -> 'bool':
        """Tell whether a buffer holds its whole datagram.

        Arguments:
            buf: buffer to check

        Returns:
            Whether the total data length is known, fits the data buffer, and
            every 8-octet block up to it is marked received.

        A datagram longer than the data buffer cannot be held, so it is never
        complete. Checking ``RCVBT`` alone does not show that: slicing it past
        its end stops silently, so the blocks past the buffer would read as
        received (:issue:`1566`).

        """
        TDL = buf.TDL
        return 0 <= TDL <= len(buf.datagram) and all(buf.RCVBT[:(TDL + 7) // 8])

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
        the octet granularity a conflict needs: every fragment but the last is
        required to be a multiple of 8 octets, and a fragment's ``FO`` is
        *always* a multiple of 8 -- it is wire-encoded in 8-octet units -- so a
        non-final fragment's range is always exactly block-aligned. The only
        block that can be *partially* real is therefore the one holding the
        final fragment's own tail: the ``RCVBT`` update in :meth:`reassembly`
        sets that block's bit across its full 8 octets even though only the
        octets up to ``tdl`` were ever actually written, the rest still being
        ``datagram``'s zero-fill.

        So once ``tdl`` is known, an octet at or past it is excluded here
        regardless of its block's bit -- comparing it would manufacture a
        conflict against a byte nothing ever really sent, over a distinction
        :meth:`~pcapkit.foundation.reassembly.ip.IP.submit` does not need
        anyway, since it never reports a payload past ``tdl``. Before ``tdl``
        is known (``tdl < 0``), every set ``rcvbt`` bit came from a non-final,
        block-aligned fragment and is exact on its own, with nothing to clip.

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

    def submit(self, buf: 'Buffer[_AT]', *, bufid: 'tuple[_AT, _AT, int, TransType]',  # type: ignore[override] # pylint: disable=arguments-differ
               checked: 'bool' = False, timeout: 'bool' = False) -> 'list[Datagram[_AT]]':
        """Submit reassembled payload.

        Arguments:
            buf: buffer dict of reassembled packets
            bufid: buffer identifier
            checked: buffer consistency checked flag
            timeout: whether this buffer is being submitted because
                :meth:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase.expire`
                abandoned it under the reassembly timeout, which is what
                separates
                :attr:`Completion.TIMEOUT <pcapkit.foundation.reassembly.data.data.Completion.TIMEOUT>`
                from
                :attr:`Completion.PARTIAL <pcapkit.foundation.reassembly.data.data.Completion.PARTIAL>`

        Returns:
            Reassembled packets.

        """
        TDL = buf.TDL
        RCVBT = buf.RCVBT
        index = buf.index
        header = buf.header
        datagram = buf.datagram
        conflict = tuple(buf.conflict)

        flag = checked or self._is_complete(buf)
        ret = []  # type: list[Datagram[_AT]]

        # How completely this datagram came out, and why it stopped. Derived once,
        # so the two branches below cannot disagree about it.
        completion = Completion.COMPLETE if flag else (
            Completion.TIMEOUT if timeout else Completion.PARTIAL
        )

        # if datagram is not implemented
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
            # still says which frames were its fragments (:issue:`1566`).
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
                # NOTE: ``analyze`` is a second full parse of the payload, and a
                # datagram is submitted for every frame rather than only for the
                # fragmented ones, so running it here charges every caller for a
                # result most of them never read. ``Deferred`` postpones it to the
                # first read of ``Datagram.packet``.
                packet=Deferred(self.protocol.analyze, bufid[3], payload),
                conflict=conflict,
            )
            ret.append(packet)

        for callback in self.__callback_fn__:
            callback(ret)
        return ret
