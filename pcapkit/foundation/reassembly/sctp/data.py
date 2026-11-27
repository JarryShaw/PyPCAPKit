# -*- coding: utf-8 -*-
"""data models for SCTP user-message reassembly

.. versionadded:: 1.9.0

"""

from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.corekit.packet import DeferredPacket
from pcapkit.foundation.reassembly.data import Deferred
from pcapkit.utilities.compat import Tuple

__all__ = [
    'Packet', 'DatagramID', 'Datagram', 'Fragment', 'Buffer', 'BufferID', 'MessageID',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional

    from typing_extensions import TypeAlias

    from pcapkit.const.sctp.chunk import Chunk as Enum_Chunk
    from pcapkit.const.sctp.payload_protocol_identifier import \
        PayloadProtocolIdentifier as Enum_PayloadProtocolIdentifier
    from pcapkit.foundation.reassembly.data import Completion
    from pcapkit.protocols.protocol import ProtocolBase

_AT = TypeVar('_AT', 'IPv4Address', 'IPv6Address')

#: Buffer ID -- the source and destination ports of the SCTP packet, plus its
#: **verification tag**, which tells the association from an earlier one
#: between the same endpoints (:rfc:`9260#section-1.3`). No address is in it,
#: as the TSN space is the association's and a chunk may be retransmitted to an
#: alternate destination address (:rfc:`9260#section-6.4`).
BufferID: 'TypeAlias' = Tuple[int, int, int]

#: Message ID of an I-DATA user message within its buffer, made of its stream
#: identifier, its ``U`` bit and its message identifier, which together find the
#: message a fragment belongs to (:rfc:`8260#section-2.2.3`).
MessageID: 'TypeAlias' = Tuple[int, bool, int]


@info_final
class Packet(Info, Generic[_AT]):
    """Data model for :term:`SCTP <reasm.sctp.packet>` user-message fragment
    representation, one DATA or I-DATA chunk."""

    #: Buffer ID.
    bufid: 'BufferID'
    #: Source address of the packet carrying the chunk.
    src: '_AT'
    #: Destination address of the packet carrying the chunk.
    dst: '_AT'
    #: Original packet range number.
    num: 'int'
    #: Chunk type, DATA or I-DATA.
    chunk: 'Enum_Chunk'
    #: Transmission sequence number.
    tsn: 'int'
    #: Stream identifier.
    stream_id: 'int'
    #: Whether the ``U`` bit is set, so the user message is unordered.
    unordered: 'bool'
    #: Whether the ``B`` bit is set, marking the first fragment of a user message.
    beginning: 'bool'
    #: Whether the ``E`` bit is set, marking the last fragment of a user message.
    ending: 'bool'
    #: Stream sequence number of a DATA chunk, as received; :data:`None` for
    #: I-DATA, which has none.
    ssn: 'Optional[int]'
    #: Message identifier of an I-DATA chunk; :data:`None` for DATA.
    mid: 'Optional[int]'
    #: Fragment sequence number of an I-DATA chunk, ``0`` on its first
    #: fragment; :data:`None` for DATA.
    fsn: 'Optional[int]'
    #: Payload protocol identifier, carried by every DATA chunk and by the first
    #: fragment of an I-DATA user message alone; :data:`None` on a later one.
    ppid: 'Optional[Enum_PayloadProtocolIdentifier]'
    #: User data of the chunk.
    payload: 'bytes'
    #: Capture timestamp of the fragment, in seconds since the Unix epoch,
    #: i.e. the *capture's* clock.
    timestamp: 'float'

    if TYPE_CHECKING:
        def __init__(self, bufid: 'tuple[int, int, int]', src: '_AT', dst: '_AT', num: 'int', chunk: 'Enum_Chunk', tsn: 'int', stream_id: 'int', unordered: 'bool', beginning: 'bool', ending: 'bool', ssn: 'Optional[int]', mid: 'Optional[int]', fsn: 'Optional[int]', ppid: 'Optional[Enum_PayloadProtocolIdentifier]', payload: 'bytes', timestamp: 'float') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class DatagramID(Info, Generic[_AT]):
    """Data model for :term:`SCTP <reasm.sctp.datagram>` original packet
    identifier.

    Its addresses are those of the message's lowest fragment held, which is its
    first fragment once the message is complete: a multi-homed association may
    carry the others over other paths.

    """

    #: Source address.
    src: '_AT'
    #: Source port.
    sport: 'int'
    #: Destination address.
    dst: '_AT'
    #: Destination port.
    dport: 'int'
    #: Verification tag the message was carried under.
    vtag: 'int'

    if TYPE_CHECKING:
        def __init__(self, src: '_AT', sport: 'int', dst: '_AT', dport: 'int', vtag: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Datagram(DeferredPacket, Info, Generic[_AT]):
    """Data model for :term:`SCTP <reasm.sctp.datagram>` reassembled user
    message."""

    #: Listing ``packet`` here is what makes :attr:`packet` lazy -- see
    #: :class:`~pcapkit.corekit.packet.DeferredPacket`.
    __additional__ = ['packet']
    #: Placeholder class :attr:`packet` may hold, for
    #: :class:`~pcapkit.corekit.packet.DeferredPacket` to resolve.
    __deferred__ = Deferred

    #: How completely the message was reassembled, and why reassembly
    #: stopped; see :class:`~pcapkit.foundation.reassembly.data.Completion`.
    completed: 'Completion'
    #: Original packet identifier.
    id: 'DatagramID[_AT]'
    #: Packet numbers of the fragments that built this message.
    index: 'tuple[int, ...]'
    #: Chunk type the message was carried in, DATA or I-DATA.
    chunk: 'Enum_Chunk'
    #: Stream identifier.
    stream_id: 'int'
    #: Whether the message is unordered.
    unordered: 'bool'
    #: Stream sequence number of an ordered DATA message; :data:`None` for an
    #: unordered one, whose number the receiver ignores
    #: (:rfc:`9260#section-3.3.1`), and for I-DATA.
    ssn: 'Optional[int]'
    #: Message identifier of an I-DATA message; :data:`None` for DATA.
    mid: 'Optional[int]'
    #: Transmission sequence numbers of the fragments held, in message order.
    tsn: 'tuple[int, ...]'
    #: Payload protocol identifier, as the first fragment held carries it;
    #: :data:`None` for an I-DATA message whose first fragment is missing.
    ppid: 'Optional[Enum_PayloadProtocolIdentifier]'
    #: Reassembled user data.
    payload: 'bytes | tuple[bytes, ...]'
    #: Parsed user data, as :func:`~pcapkit.foundation.analysis.sctp.sctp_message`
    #: returns it unless the reassembly's ``__protocol_type__`` names another
    #: protocol, which then parses it instead. Parsed on first read, not at
    #: construction time, and :data:`None` for the tuple of runs ``strict=True``
    #: reports. A :class:`~pcapkit.foundation.reassembly.data.Deferred` may be
    #: passed in its place, and reading this attribute then runs it and keeps
    #: the result.
    packet: 'Optional[ProtocolBase]'

    if TYPE_CHECKING:
        def __init__(self, completed: 'Completion', id: 'DatagramID[_AT]', index: 'tuple[int, ...]', chunk: 'Enum_Chunk', stream_id: 'int', unordered: 'bool', ssn: 'Optional[int]', mid: 'Optional[int]', tsn: 'tuple[int, ...]', ppid: 'Optional[Enum_PayloadProtocolIdentifier]', payload: 'bytes | tuple[bytes, ...]', packet: 'Optional[ProtocolBase | Deferred[Optional[Enum_PayloadProtocolIdentifier]]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Fragment(Info, Generic[_AT]):
    """Data model for :term:`SCTP <reasm.sctp.buffer>` user message under
    construction.

    Its fragments are ordered by a sequence number: the TSN for DATA
    (:rfc:`9260#section-6.9`) and the FSN for I-DATA
    (:rfc:`8260#section-2.2.3`), both 32-bit serial numbers.

    """

    #: Numbers of the packets merged into this message.
    ind: 'list[int]'
    #: Chunk type, DATA or I-DATA.
    chunk: 'Enum_Chunk'
    #: Stream identifier.
    stream_id: 'int'
    #: Whether the message is unordered.
    unordered: 'bool'
    #: Stream sequence number of an ordered DATA message; :data:`None` otherwise.
    ssn: 'Optional[int]'
    #: Message identifier of an I-DATA message; :data:`None` for DATA.
    mid: 'Optional[int]'
    #: Payload protocol identifier, that of the lowest DATA fragment held or of
    #: the first I-DATA fragment; :data:`None` until it arrives.
    ppid: 'Optional[Enum_PayloadProtocolIdentifier]'
    #: Source address of the packet carrying the lowest fragment held.
    src: '_AT'
    #: Destination address of the packet carrying the lowest fragment held.
    dst: '_AT'
    #: Sequence number of the lowest fragment held.
    head: 'int'
    #: Sequence number of the highest fragment held.
    tail: 'int'
    #: Whether the fragment at :attr:`head` has the ``B`` bit set.
    beginning: 'bool'
    #: Whether the fragment at :attr:`tail` has the ``E`` bit set.
    ending: 'bool'
    #: Each fragment held, by sequence number, as its TSN and user data.
    parts: 'dict[int, tuple[int, bytes]]'

    if TYPE_CHECKING:
        def __init__(self, ind: 'list[int]', chunk: 'Enum_Chunk', stream_id: 'int', unordered: 'bool', ssn: 'Optional[int]', mid: 'Optional[int]', ppid: 'Optional[Enum_PayloadProtocolIdentifier]', src: '_AT', dst: '_AT', head: 'int', tail: 'int', beginning: 'bool', ending: 'bool', parts: 'dict[int, tuple[int, bytes]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Buffer(Info):
    """Data model for :term:`SCTP <reasm.sctp.buffer>` buffer entry -- every
    user message being reassembled under one :data:`BufferID`, i.e. one
    direction of one association, over every path it takes."""

    #: DATA messages under construction, by the TSN of every fragment each
    #: holds: a run of consecutive TSNs (:rfc:`9260#section-3.3.1`).
    tsn: 'dict[int, Fragment]'
    #: I-DATA messages under construction, by :data:`MessageID`.
    msg: 'dict[MessageID, Fragment]'
    #: Capture timestamp of the first fragment buffered under this buffer ID,
    #: in seconds since the Unix epoch.
    timestamp: 'float'

    if TYPE_CHECKING:
        def __init__(self, tsn: 'dict[int, Fragment]', msg: 'dict[tuple[int, bool, int], Fragment]', timestamp: 'float') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
