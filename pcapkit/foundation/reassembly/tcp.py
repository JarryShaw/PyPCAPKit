# -*- coding: utf-8 -*-
"""TCP Datagram Reassembly
=============================

.. module:: pcapkit.foundation.reassembly.tcp

:mod:`pcapkit.foundation.reassembly.tcp` contains
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` only,
which reconstructs fragmented TCP packets back to origin.

"""
import sys
from typing import TYPE_CHECKING

from pcapkit.foundation.reassembly.data.tcp import (Buffer, BufferID, Datagram, DatagramID,
                                                    Fragment, HoleDiscriptor, Packet)
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

    Example:
        >>> from pcapkit.foundation.reassembly import TCP
        # Initialise instance:
        >>> tcp_reassembly = TCP()
        # Call reassembly:
        >>> tcp_reassembly(packet_dict)
        # Fetch result:
        >>> result = tcp_reassembly.datagram

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

        BUFID = info.bufid  # Buffer Identifier
        DSN = info.dsn      # Data Sequence Number
        ACK = info.ack      # Acknowledgement Number
        FIN = info.fin      # Finish Flag (Termination)
        RST = info.rst      # Reset Connection Flag (Termination)
        SYN = info.syn      # Synchronise Flag (Establishment)

        # when SYN is set, reset buffer of existing session
        if SYN and BUFID in self._buffer:
            self._dtgram.extend(
                self.submit(self._buffer.pop(BUFID), bufid=BUFID)
            )

        # initialise buffer with BUFID & ACK
        if BUFID not in self._buffer:
            self._buffer[BUFID] = Buffer(
                hdl=[
                    HoleDiscriptor(
                        first=info.len,
                        last=sys.maxsize,
                    ),
                ],
                hdr=info.header if SYN else b'',
                ack={
                    ACK: Fragment(
                        ind=[
                            info.num,
                        ],
                        isn=info.dsn,
                        len=info.len,
                        raw=info.payload,
                    ),
                },
            )
        else:
            # initialise buffer with ACK
            if ACK not in self._buffer[BUFID].ack:
                self._buffer[BUFID].ack[ACK] = Fragment(
                    ind=[
                        info.num,
                    ],
                    isn=info.dsn,
                    len=info.len,
                    raw=info.payload,
                )
            else:
                # put header into header buffer
                if SYN:
                    self._buffer[BUFID].__update__(hdr=info.header)

                # append packet index
                self._buffer[BUFID].ack[ACK].ind.append(info.num)

                # record fragment payload
                ISN = self._buffer[BUFID].ack[ACK].isn       # Initial Sequence Number
                RAW = self._buffer[BUFID].ack[ACK].raw       # Raw Payload Data
                if DSN >= ISN:  # if fragment goes after existing payload
                    LEN = self._buffer[BUFID].ack[ACK].len
                    GAP = DSN - (ISN + LEN)     # gap length between payloads
                    if GAP >= 0:    # if fragment goes after existing payload
                        RAW += bytearray(GAP) + info.payload
                    else:           # if fragment partially overlaps existing payload
                        RAW[DSN-ISN:] = info.payload
                else:           # if fragment exceeds existing payload
                    LEN = info.len
                    GAP = ISN - (DSN + LEN)     # gap length between payloads
                    self._buffer[BUFID].ack[ACK].__update__(
                        isn=DSN,
                    )
                    if GAP >= 0:    # if fragment exceeds existing payload
                        RAW = info.payload + bytearray(GAP) + RAW
                    else:           # if fragment partially overlaps existing payload
                        RAW = info.payload + RAW[ISN-GAP:]
                #self._buffer[BUFID].ack[ACK].raw = RAW       # update payload datagram
                #self._buffer[BUFID].ack[ACK].len = len(RAW)  # update payload length
                self._buffer[BUFID].ack[ACK].__update__(
                    raw=RAW,       # update payload datagram
                    len=len(RAW),  # update payload length
                )

            # update hole descriptor list
            HDL = self._buffer[BUFID].hdl                          # HDL alias
            for (index, hole) in enumerate(HDL):                   # step one
                if info.first > hole.last:                         # step two
                    continue
                if info.last < hole.first:                         # step three
                    continue
                del HDL[index]                                     # step four
                if info.first > hole.first:                        # step five
                    new_hole = HoleDiscriptor(
                        first=hole.first,
                        last=info.first - 1,
                    )
                    HDL.insert(index, new_hole)
                    index += 1
                if info.last < hole.last and not FIN and not RST:  # step six
                    new_hole = HoleDiscriptor(
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

    def submit(self, buf: 'Buffer', *, bufid: 'BufferID') -> 'list[Datagram]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Submit reassembled payload.

        Arguments:
            buf: :term:`buffer <reasm.tcp.buffer>` dict of reassembled packets
            bufid: buffer identifier

        Returns:
            Reassembled :term:`packets <reasm.tcp.datagram>`.

        """
        datagram = []  # type: list[Datagram] # reassembled datagram
        HDL = buf.hdl                         # hole descriptor list

        # check through every buffer with ACK
        for (ack, buffer) in buf.ack.items():
            # if this buffer is not implemented
            # go through every hole and extract received payload
            if len(HDL) > 2 and self._flag_s:
                data = []  # type: list[bytes]
                start = stop = 0
                for hole in HDL:
                    stop = hole.first
                    byte = buffer.raw[start:stop]
                    start = hole.last
                    if byte:    # strip empty payload
                        data.append(byte)
                byte = buffer.raw[start:]
                if byte:    # strip empty payload
                    data.append(bytes(byte))
                if data:    # strip empty buffer
                    packet = Datagram(
                        completed=False,
                        id=DatagramID(
                            src=(bufid[0], bufid[1]),
                            dst=(bufid[2], bufid[3]),
                            ack=ack,
                        ),
                        index=tuple(buffer.ind),
                        header=buf.hdr,
                        payload=tuple(data),
                        packet=None,
                    )
                    datagram.append(packet)

            # if this buffer is implemented
            # export payload data & convert into bytes
            else:
                payload = buffer.raw
                if payload:    # strip empty buffer
                    packet = Datagram(
                        completed=True,
                        id=DatagramID(
                            src=(bufid[0], bufid[1]),
                            dst=(bufid[2], bufid[3]),
                            ack=ack,
                        ),
                        index=tuple(buffer.ind),
                        header=buf.hdr,
                        payload=bytes(payload),
                        packet=self.protocol.analyze((bufid[1], bufid[3]), bytes(payload)),
                    )
                    datagram.append(packet)

        for callback in self.__callback_fn__:
            callback(datagram)
        return datagram
