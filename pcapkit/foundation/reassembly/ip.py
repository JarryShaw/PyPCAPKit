# -*- coding: utf-8 -*-
"""IP Datagram Reassembly
============================

:mod:`pcapkit.foundation.reassembly.ip` contains
:class:`~pcapkit.foundation.reassembly.ip.IP_Reassembly`
only, which reconstructs fragmented IP packets back to
origin. The following algorithm implement is based on IP
reassembly procedure introduced in :rfc:`791`, using
``RCVBT`` (fragment receivedbit table). Though another
algorithm is explained in :rfc:`815`, replacing ``RCVBT``,
however, this implement still used the elder one.

"""
from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info
from pcapkit.foundation.reassembly.reassembly import Reassembly

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional, overload

    from typing_extensions import Literal

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.protocols.protocol import Protocol

__all__ = ['IP_Reassembly']

AT = TypeVar('AT', 'IPv4Address', 'IPv6Address')

###############################################################################
# Data Models
###############################################################################


class Packet(Info, Generic[AT]):
    """Data model for :term:`ipv4.packet` / :term:`ipv6.packet`."""

    #: Buffer ID.
    bufid: 'tuple[AT, AT, int, TransType]'
    #: Original packet range number.
    num: 'int'
    #: Fragment offset.
    fo: 'int'
    #: Internet header length.
    ihl: 'int'
    #: More fragments flag.
    mf: 'bool'
    #: Total length, header included.
    tl: 'int'
    #: Raw :obj:`bytes` type header.
    header: 'bytes'
    #: Raw :obj:`bytearray` type payload.
    payload: 'bytearray'

    if TYPE_CHECKING:
        def __init__(self, bufid: 'tuple[AT, AT, int, TransType]', num: 'int', fo: 'int', ihl: 'int', mf: 'bool', tl: 'int', header: 'bytes', payload: 'bytearray') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class DatagramID(Info, Generic[AT]):
    """Data model for :term:`ipv4.datagram` / :term:`ipv6.datagram` original packet identifier."""

    #: Source address.
    src: 'AT'
    #: Destination address.
    dst: 'AT'
    #: IP protocol identifier.
    id: 'int'
    #: Payload protocol type.
    proto: 'TransType'

    if TYPE_CHECKING:
        def __init__(self, src: 'AT', dst: 'AT', id: 'int', proto: 'TransType') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Datagram(Info, Generic[AT]):
    """Data model for :term:`ipv4.datagram` / :term:`ipv6.datagram`."""

    #: Completed flag.
    completed: 'bool'
    #: Original packet identifier.
    id: 'DatagramID[AT]'
    #: Packet numbers.
    index: 'tuple[int, ...]'
    #: Initial IP header.
    header: 'bytes'
    #: Reassembled IP payload.
    payload: 'bytes | tuple[bytes, ...]'
    #: Parsed IP payload.
    packet: 'Optional[Protocol]'

    if TYPE_CHECKING:
        @overload  #pylint: disable=used-before-assignment
        def __init__(self, completed: 'Literal[True]', id: 'DatagramID[AT]', index: 'tuple[int, ...]', header: 'bytes', payload: 'bytes', packet: 'Protocol') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

        @overload
        def __init__(self, completed: 'Literal[False]', id: 'DatagramID[AT]', index: 'tuple[int, ...]', header: 'bytes', payload: 'tuple[bytes, ...]', packet: 'None') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

        def __init__(self, completed: 'bool', id: 'DatagramID[AT]', index: 'tuple[int, ...]', header: 'bytes', payload: 'bytes | tuple[bytes, ...]', packet: 'Optional[Protocol]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Buffer(Info, Generic[AT]):
    """Data model for :term:`ipv4.buffer` / :term:`ipv6.buffer`."""

    #: Total data length.
    TDL: 'int'
    #: Fragment received bit table.
    RCVBT: 'bytearray'
    #: List of reassembled packets.
    index: 'list[int]'
    #: Header buffer.
    header: 'bytes'
    #: Data buffer, holes set to ``b'\x00'``.
    datagram: 'bytearray'

    if TYPE_CHECKING:
        def __init__(self, TDL: 'int', RCVBT: 'bytearray', index: 'list[int]', header: 'bytes', datagram: 'bytearray') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


###############################################################################
# Algorithm Implementation
###############################################################################


class IP_Reassembly(Reassembly[Packet[AT], Datagram[AT], tuple[AT, AT, 'int', 'TransType'], Buffer[AT]], Generic[AT]):  # pylint: disable=abstract-method
    """Reassembly for IP payload.

    Important:
        This class is not intended to be instantiated directly,
        but rather used as a base class for the protocol-aware
        reassembly classes.

    """

    ##########################################################################
    # Methods.
    ##########################################################################

    def reassembly(self, info: 'Packet[AT]') -> 'None':
        """Reassembly procedure.

        Arguments:
            info: info dict of packets to be reassembled

        """
        BUFID = info.bufid  # Buffer Identifier
        FO = info.fo        # Fragment Offset
        IHL = info.ihl      # Internet Header Length
        MF = info.mf        # More Fragments flag
        TL = info.tl        # Total Length

        # when non-fragmented (possibly discarded) packet received
        if not FO and not MF:
            if BUFID in self._buffer:
                self._dtgram.extend(
                    self.submit(self._buffer.pop(BUFID), bufid=BUFID)
                )
                return

        # initialise buffer with BUFID
        if BUFID not in self._buffer:
            self._buffer[BUFID] = Buffer(
                TDL=-1,                              # Total Data Length
                RCVBT=bytearray(8191),              # Fragment Received Bit Table
                index=[],                           # index record
                header=b'' if FO else info.header,  # header buffer
                datagram=bytearray(65535),          # data buffer
            )
        else:
            # put header into header buffer
            if not FO:  # pylint: disable=else-if-used
                self._buffer[BUFID].__update__(header=info.header)

        # append packet index
        self._buffer[BUFID].index.append(info.num)

        # put data into data buffer
        start = FO
        stop = TL - IHL + FO
        self._buffer[BUFID].datagram[start:stop] = info.payload

        # set RCVBT bits (in 8 octets)
        start = FO // 8
        stop = FO // 8 + (TL - IHL + 7) // 8
        self._buffer[BUFID].RCVBT[start:stop] = b'\x01' * (stop - start + 1)

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

    def submit(self, buf: 'Buffer[AT]', *, bufid: 'tuple[AT, AT, int, TransType]',  # type: ignore[override] # pylint: disable=arguments-differ
               checked: 'bool' = False) -> 'list[Datagram[AT]]':
        """Submit reassembled payload.

        Arguments:
            buf: buffer dict of reassembled packets
            bufid: buffer identifier
            checked: buffer consistency checked flag

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
        flag = checked or (TDL and all(RCVBT[start:stop]))
        # if datagram is not implemented
        if not flag and self._strflg:
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
                    completed=False,
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
        # if datagram is reassembled in whole
        else:
            payload = datagram[:TDL]
            packet = Datagram(
                completed=True,
                id=DatagramID(
                    src=bufid[0],
                    dst=bufid[1],
                    id=bufid[2],
                    proto=bufid[3],
                ),
                index=tuple(index),
                header=header,
                payload=bytes(payload),
                packet=self.protocol.analyze(bufid[3], bytes(payload)),
            )
        return [packet]
