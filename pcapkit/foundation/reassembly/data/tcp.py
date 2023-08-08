# -*- coding: utf-8 -*-
"""data models for TCP reassembly"""

from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.utilities.compat import Tuple

__all__ = [
    'Packet', 'DatagramID', 'Datagram', 'HoleDiscriptor',
    'Fragment', 'Buffer', 'BufferID',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional

    from typing_extensions import TypeAlias

    from pcapkit.protocols.protocol import Protocol

IPAddress = TypeVar('IPAddress', 'IPv4Address', 'IPv6Address')

#: Buffer ID.
BufferID: 'TypeAlias' = Tuple[IPAddress, int, IPAddress, int]


@info_final
class Packet(Info):
    """Data model for :term:`reasm.tcp.packet`."""

    #: Buffer ID.
    bufid: 'BufferID'
    #: Data sequence number.
    dsn: 'int'
    #: Acknowledgment number.
    ack: 'int'
    #: Original packet range number.
    num: 'int'
    #: Synchronise flag.
    syn: 'bool'
    #: Finish flag.
    fin: 'bool'
    #: Reset connection flag.
    rst: 'bool'
    #: Payload length, header excluded.
    len: 'int'
    #: This sequence number.
    first: 'int'
    #: Next (wanted) sequence number.
    last: 'int'
    #: Raw :obj:`bytes` type header.
    header: 'bytes'
    #: Raw :obj:`bytearray` type payload.
    payload: 'bytearray'


@info_final
class DatagramID(Info, Generic[IPAddress]):
    """Data model for :term:`reasm.tcp.datagram` original packet identifier."""

    #: Source address.
    src: 'tuple[IPAddress, int]'
    #: Destination address.
    dst: 'tuple[IPAddress, int]'
    #: Original packet ACK number.
    ack: 'int'


@info_final
class Datagram(Info, Generic[IPAddress]):
    """Data model for :term:`reasm.tcp.datagram`."""

    #: Completed flag.
    completed: 'bool'
    #: Original packet identifier.
    id: 'DatagramID[IPAddress]'
    #: Packet numbers.
    index: 'tuple[int, ...]'
    #: Initial TCP header.
    header: 'bytes'
    #: Reassembled payload (application layer data).
    payload: 'bytes | tuple[bytes, ...]'
    #: Parsed reassembled payload.
    packet: 'Optional[Protocol]'


@info_final
class HoleDiscriptor(Info):
    """Data model for :term:`reasm.tcp.buffer` hole descriptor."""

    #: Start of hole.
    first: 'int'
    #: Stop of hole.
    last: 'int'


@info_final
class Fragment(Info):
    """Data model for :term:`reasm.tcp.buffer` ACK list fragment item."""

    #: List of reassembled packets.
    ind: 'list[int]'
    #: ISN of payload buffer.
    isn: 'int'
    #: Length of payload buffer.
    len: 'int'
    #: Reassembled payload holes set to b'\x00'.
    raw: 'bytearray'


@info_final
class Buffer(Info):
    """Data model for :term:`reasm.tcp.buffer`."""

    #: Hole descriptor list.
    hdl: 'list[HoleDiscriptor]'
    #: Initial TCP header.
    hdr: 'bytes'
    #: ACK list.
    ack: 'dict[int, Fragment]'
