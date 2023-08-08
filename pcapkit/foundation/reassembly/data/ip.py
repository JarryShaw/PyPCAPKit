# -*- coding: utf-8 -*-
"""data models for IP reassembly"""

from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.utilities.compat import Tuple

__all__ = [
    'Packet', 'DatagramID', 'Datagram', 'Buffer', 'BufferID',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional

    from typing_extensions import TypeAlias

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.protocols.protocol import Protocol

AT = TypeVar('AT', 'IPv4Address', 'IPv6Address')

#: Buffer ID.
BufferID: 'TypeAlias' = Tuple[AT, AT, int, 'TransType']


@info_final
class Packet(Info, Generic[AT]):
    """Data model for :term:`reasm.ipv4.packet` / :term:`reasm.ipv6.packet`."""

    #: Buffer ID.
    bufid: 'BufferID'
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


@info_final
class DatagramID(Info, Generic[AT]):
    """Data model for :term:`reasm.ipv4.datagram` / :term:`reasm.ipv6.datagram` original packet identifier."""

    #: Source address.
    src: 'AT'
    #: Destination address.
    dst: 'AT'
    #: IP protocol identifier.
    id: 'int'
    #: Payload protocol type.
    proto: 'TransType'


@info_final
class Datagram(Info, Generic[AT]):
    """Data model for :term:`reasm.ipv4.datagram` / :term:`reasm.ipv6.datagram`."""

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


@info_final
class Buffer(Info, Generic[AT]):
    """Data model for :term:`reasm.ipv4.buffer` / :term:`reasm.ipv6.buffer`."""

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
