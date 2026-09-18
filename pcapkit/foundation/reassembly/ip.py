# -*- coding: utf-8 -*-
"""IP Datagram Reassembly
============================

.. module:: pcapkit.foundation.reassembly.ip

:mod:`pcapkit.foundation.reassembly.ip` contains
:class:`~pcapkit.foundation.reassembly.ip.IP`
only, which reconstructs fragmented IP packets back to
origin. The following algorithm implement is based on IP
reassembly procedure introduced in :rfc:`791`, using
``RCVBT`` (fragment receivedbit table). Though another
algorithm is explained in :rfc:`815`, replacing ``RCVBT``,
however, this implement still used the elder one.

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.foundation.reassembly.data.data import Completion
from pcapkit.foundation.reassembly.data.ip import (_AT, Buffer, BufferID, Datagram, DatagramID,
                                                   Deferred, Packet)
from pcapkit.foundation.reassembly.reassembly import ReassemblyBase as Reassembly

if TYPE_CHECKING:
    from typing import Type

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.protocols.internet.ip import IP as IP_Protocol

__all__ = ['IP']


class IP(Reassembly[Packet[_AT], Datagram[_AT], BufferID, Buffer[_AT]], Generic[_AT]):  # pylint: disable=abstract-method
    """Reassembly for IP payload.

    Args:
        strict: if return all datagrams (including those not
                implemented) when submit
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

        # initialise buffer with BUFID
        if BUFID not in self._buffer:
            self._buffer[BUFID] = Buffer(
                TDL=-1,                              # Total Data Length
                RCVBT=bytearray(8191),              # Fragment Received Bit Table
                index=[],                           # index record
                header=header,                      # header buffer
                datagram=bytearray(65535),          # data buffer
                timestamp=TS,                       # first-arriving fragment's clock reading
            )
        else:
            # put header into header buffer
            if not FO:  # pylint: disable=else-if-used
                self._buffer[BUFID].__update__(header=header)

        # append packet index
        self._buffer[BUFID].index.append(info.num)

        # put data into data buffer
        start = FO
        stop = TL - IHL + FO
        self._buffer[BUFID].datagram[start:stop] = info.payload

        # set RCVBT bits (in 8 octets)
        start = FO // 8
        stop = FO // 8 + (TL - IHL + 7) // 8
        self._buffer[BUFID].RCVBT[start:stop] = b'\x01' * (stop - start)

        # get total data length (header excludes)
        TDL = 0
        if not MF:
            TDL = TL - IHL + FO
            self._buffer[BUFID].__update__(TDL=TDL)

        # when datagram is reassembled in whole
        start = 0
        stop = (TDL + 7) // 8
        if TDL and all(self._buffer[BUFID].RCVBT[start:stop]):
            self._dtgram.extend(
                self.submit(self._buffer.pop(BUFID), bufid=BUFID, checked=True)
            )

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

        start = 0
        stop = (TDL + 7) // 8
        flag = checked or (TDL > 0 and all(RCVBT[start:stop]))
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
            # extract received payload
            for (bctr, bit) in enumerate(RCVBT):
                if bit:     # received bit
                    this = bctr * 8
                    that = this + 8
                    byte += datagram[this:that]
                else:       # missing bit
                    if byte:    # strip empty payload
                        data.append(bytes(byte))
                    byte = bytearray()
            # strip empty packets
            if data or header:
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
                )
                ret.append(packet)
        # if datagram is reassembled in whole -- or if it is not, and ``strict``
        # asked for one contiguous payload rather than the received runs
        else:
            # ``TDL`` is the datagram's total length, and it is only known once the
            # fragment with **MF** clear has arrived -- until then it is still its
            # initial ``-1``. Which case this is decides how much of the buffer
            # there is to report.
            if TDL > 0:
                # The length is known. Report it, holes and all: the gaps read as
                # zeros, exactly as they do in the TCP reassembler's loose mode.
                # This is unchanged behaviour, and the reason ``strict=False``
                # exists -- a caller who wants the gaps *marked* rather than
                # zero-filled uses ``strict=True`` and gets the runs.
                stop = TDL
            else:
                # The length is not known, and this is the case that used to slice
                # ``datagram[:-1]`` -- handing back 65534 octets of the
                # preallocated buffer, almost all of them zeros the sender never
                # sent, and calling the result complete.
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
                # the first clear bit.
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
            )
            ret.append(packet)

        for callback in self.__callback_fn__:
            callback(ret)
        return ret
