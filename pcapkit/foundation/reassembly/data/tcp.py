# -*- coding: utf-8 -*-
"""data models for TCP reassembly"""

from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.utilities.compat import Tuple

__all__ = [
    'Packet', 'DatagramID', 'Datagram', 'HoleDescriptor',
    'Fragment', 'Buffer', 'BufferID',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional, overload

    from typing_extensions import Literal, TypeAlias

    from pcapkit.protocols.protocol import ProtocolBase as Protocol

_AT = TypeVar('_AT', 'IPv4Address', 'IPv6Address')

#: Buffer ID.
BufferID: 'TypeAlias' = Tuple[_AT, int, _AT, int]


@info_final
class Packet(Info):
    """Data model for :term:`TCP <reasm.tcp.packet>` packet representation."""

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
    #: Sequence number of the first octet of :attr:`payload`, i.e. the segment's
    #: own sequence number. Absolute, not an offset into any payload buffer.
    first: 'int'
    #: Sequence number of the last octet of :attr:`payload`, i.e. ``first +
    #: len - 1``. **Inclusive**, so a segment carrying no payload at all has
    #: :attr:`last` one below :attr:`first`.
    last: 'int'
    #: Raw :obj:`bytes` type header.
    header: 'bytes'
    #: Raw :obj:`bytearray` type payload.
    payload: 'bytearray'

    if TYPE_CHECKING:
        def __init__(self, bufid: 'BufferID', dsn: 'int', ack: 'int', num: 'int', syn: 'bool', fin: 'bool', rst: 'bool', len: 'int', first: 'int', last: 'int', header: 'bytes', payload: 'bytearray') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class DatagramID(Info, Generic[_AT]):
    """Data model for :term:`TCP <reasm.tcp.datagram>` original packet identifier."""

    #: Source address.
    src: 'tuple[_AT, int]'
    #: Destination address.
    dst: 'tuple[_AT, int]'
    #: Original packet ACK number.
    ack: 'int'

    if TYPE_CHECKING:
        def __init__(self, src: 'tuple[_AT, int]', dst: 'tuple[_AT, int]', ack: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Datagram(Info, Generic[_AT]):
    """Data model for :term:`TCP <reasm.tcp.datagram>`."""

    #: Completed flag.
    completed: 'bool'
    #: Original packet identifier.
    id: 'DatagramID[_AT]'
    #: Packet numbers.
    index: 'tuple[int, ...]'
    #: Initial TCP header.
    header: 'bytes'
    #: Reassembled payload (application layer data).
    payload: 'bytes | tuple[bytes, ...]'
    #: Parsed reassembled payload.
    packet: 'Optional[Protocol]'

    if TYPE_CHECKING:
        @overload  # pylint: disable=used-before-assignment
        def __init__(self, completed: 'Literal[True]', id: 'DatagramID[_AT]', index: 'tuple[int, ...]', header: 'bytes', payload: 'bytes', packet: 'Protocol') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

        @overload
        def __init__(self, completed: 'Literal[False]', id: 'DatagramID[_AT]', index: 'tuple[int, ...]', header: 'bytes', payload: 'tuple[bytes, ...]', packet: 'None') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

        def __init__(self, completed: 'bool', id: 'DatagramID[_AT]', index: 'tuple[int, ...]', header: 'bytes', payload: 'bytes | tuple[bytes, ...]', packet: 'Optional[Protocol]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class HoleDescriptor(Info):
    """Data model for :term:`TCP <reasm.tcp.buffer>` hole descriptor.

    Both bounds are **absolute TCP sequence numbers** and both are
    **inclusive**, so a hole covers ``last - first + 1`` octets. They are not
    offsets into :attr:`Fragment.raw`: the descriptor list is kept once per
    buffer ID, whereas each acknowledgement number's payload buffer carries an
    initial sequence number of its own, so only
    :meth:`TCP.submit <pcapkit.foundation.reassembly.tcp.TCP.submit>` -- which
    knows which buffer it is looking at -- can convert one to the other.

    """

    #: Sequence number of the first missing octet.
    first: 'int'
    #: Sequence number of the last missing octet, inclusive.
    last: 'int'

    if TYPE_CHECKING:
        def __init__(self, first: 'int', last: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Fragment(Info):
    """Data model for :term:`TCP <reasm.tcp.buffer>` ACK list fragment item."""

    #: List of reassembled packets.
    ind: 'list[int]'
    #: Sequence number of the octet held in ``raw[0]``, i.e. the origin this
    #: buffer is indexed from: ``raw[n]`` holds the octet whose sequence number
    #: is ``isn + n``. Revised downwards whenever a segment turns up below the
    #: data already buffered, so it is not necessarily the connection's own
    #: initial sequence number.
    isn: 'int'
    #: Length of payload buffer.
    len: 'int'
    #: Reassembled payload holes set to b'\x00'.
    raw: 'bytearray'

    if TYPE_CHECKING:
        def __init__(self, ind: 'list[int]', isn: 'int', len: 'int', raw: 'bytearray') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Buffer(Info):
    """Data model for :term:`TCP <reasm.tcp.buffer>` buffer entry."""

    #: Hole descriptor list.
    hdl: 'list[HoleDescriptor]'
    #: Initial TCP header.
    hdr: 'bytes'
    #: ACK list.
    ack: 'dict[int, Fragment]'

    if TYPE_CHECKING:
        def __init__(self, hdl: 'list[HoleDescriptor]', hdr: 'bytes', ack: 'dict[int, Fragment]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin
