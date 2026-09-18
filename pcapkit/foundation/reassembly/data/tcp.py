# -*- coding: utf-8 -*-
"""data models for TCP reassembly"""

from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.foundation.reassembly.data.data import Completion, Deferred, DeferredPacket
from pcapkit.utilities.compat import Tuple

__all__ = [
    'Packet', 'DatagramID', 'Datagram', 'HoleDescriptor',
    'Fragment', 'Buffer', 'BufferID',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional

    from typing_extensions import TypeAlias

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
    #: Capture timestamp of the segment, in seconds since the Unix epoch, i.e.
    #: the *capture's* clock rather than the host's. It drives the reassembly
    #: timeout, which for TCP is off by default -- see
    #: :attr:`TCP.__timeout__ <pcapkit.foundation.reassembly.tcp.TCP.__timeout__>`.
    timestamp: 'float'

    if TYPE_CHECKING:
        def __init__(self, bufid: 'BufferID', dsn: 'int', ack: 'int', num: 'int', syn: 'bool', fin: 'bool', rst: 'bool', len: 'int', first: 'int', last: 'int', header: 'bytes', payload: 'bytearray', timestamp: 'float') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


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
class Datagram(DeferredPacket, Info, Generic[_AT]):
    """Data model for :term:`TCP <reasm.tcp.datagram>`."""

    #: How completely the datagram was reassembled, and why reassembly stopped;
    #: see :class:`~pcapkit.foundation.reassembly.data.data.Completion`. Only
    #: :attr:`Completion.COMPLETE` is truthy, so ``if datagram.completed:`` reads
    #: as it did while this was a :obj:`bool`.
    completed: 'Completion'
    #: Listing ``packet`` here is what makes it lazy -- see
    #: :class:`~pcapkit.foundation.reassembly.data.data.DeferredPacket`.
    __additional__ = ['packet']

    #: Original packet identifier.
    id: 'DatagramID[_AT]'
    #: Packet numbers.
    index: 'tuple[int, ...]'
    #: Initial TCP header.
    header: 'bytes'
    #: Reassembled payload (application layer data).
    payload: 'bytes | tuple[bytes, ...]'
    #: Parsed reassembled payload.
    #: Parsed TCP payload. Analysed on first read rather than at construction;
    #: a :class:`Deferred` may be passed in its place.
    packet: 'Optional[Protocol]'

    if TYPE_CHECKING:
        # NOTE: one signature rather than a pair of ``@overload``\\ s keyed on
        # ``completed`` -- for the reason given on
        # :class:`~pcapkit.foundation.reassembly.data.ip.Datagram`, which applies
        # here identically: ``strict=False`` reports an incomplete payload buffer as
        # one contiguous ``bytes`` and analyses it.
        def __init__(self, completed: 'Completion', id: 'DatagramID[_AT]', index: 'tuple[int, ...]', header: 'bytes', payload: 'bytes | tuple[bytes, ...]', packet: 'Optional[Protocol | Deferred]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


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
    #: Capture timestamp of the **first** segment buffered under this buffer ID,
    #: in seconds since the Unix epoch. Origin of the reassembly timer, and never
    #: revised: a later segment does not extend the deadline.
    timestamp: 'float'

    if TYPE_CHECKING:
        def __init__(self, hdl: 'list[HoleDescriptor]', hdr: 'bytes', ack: 'dict[int, Fragment]', timestamp: 'float') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin
