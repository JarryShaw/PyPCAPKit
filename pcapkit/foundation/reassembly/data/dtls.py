# -*- coding: utf-8 -*-
"""data models for DTLS handshake-message reassembly"""

from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.utilities.compat import Tuple

__all__ = [
    'Packet', 'DatagramID', 'Datagram', 'HoleDescriptor', 'Fragment', 'Buffer', 'BufferID',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional

    from typing_extensions import TypeAlias

    from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType
    from pcapkit.foundation.reassembly.data.data import Completion

_AT = TypeVar('_AT', 'IPv4Address', 'IPv6Address')

#: Buffer ID -- the UDP 4-tuple (addresses and ports; the protocol is always
#: UDP, so it is left out), plus the DTLS **epoch**: the record sequence
#: number resets on every change of cipher state (:rfc:`6347#section-4.1`), so
#: a fragment from a new epoch belongs to a fresh buffer rather than the one
#: its 4-tuple would otherwise name.
BufferID: 'TypeAlias' = Tuple[_AT, int, _AT, int, int]


@info_final
class Packet(Info, Generic[_AT]):
    """Data model for :term:`DTLS <reasm.dtls.packet>` handshake-fragment
    representation."""

    #: Buffer ID.
    bufid: 'BufferID'
    #: Original packet range number.
    num: 'int'
    #: Handshake message type.
    msg_type: 'Enum_HandshakeType'
    #: Total message length (:rfc:`6347#section-4.2.2`'s ``length``), fragment
    #: headers and bodies excluded -- the same on every fragment of one
    #: message.
    length: 'int'
    #: Message sequence number, the datagram key within :attr:`bufid`.
    message_seq: 'int'
    #: Fragment offset into the reassembled message.
    fragment_offset: 'int'
    #: Length of this fragment.
    fragment_length: 'int'
    #: Raw fragment payload.
    payload: 'bytes'
    #: Capture timestamp of the fragment, in seconds since the Unix epoch,
    #: i.e. the *capture's* clock. Recorded only; it does not expire anything.
    timestamp: 'float'

    if TYPE_CHECKING:
        def __init__(self, bufid: 'tuple[_AT, int, _AT, int, int]', num: 'int', msg_type: 'Enum_HandshakeType', length: 'int', message_seq: 'int', fragment_offset: 'int', fragment_length: 'int', payload: 'bytes', timestamp: 'float') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class DatagramID(Info, Generic[_AT]):
    """Data model for :term:`DTLS <reasm.dtls.datagram>` original packet
    identifier."""

    #: Source address.
    src: '_AT'
    #: Source port.
    sport: 'int'
    #: Destination address.
    dst: '_AT'
    #: Destination port.
    dport: 'int'
    #: Epoch the message was reassembled under.
    epoch: 'int'

    if TYPE_CHECKING:
        def __init__(self, src: '_AT', sport: 'int', dst: '_AT', dport: 'int', epoch: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Datagram(Info, Generic[_AT]):
    """Data model for :term:`DTLS <reasm.dtls.datagram>` reassembled
    handshake message.

    :attr:`body` is reported eagerly, not through a
    :class:`~pcapkit.foundation.reassembly.data.data.Deferred`: a message only
    reaches :meth:`DTLS.submit <pcapkit.foundation.reassembly.dtls.DTLS.submit>`
    because it was fragmented, so there is no common unfragmented case to
    keep cheap.

    """

    #: How completely the message was reassembled, and why reassembly
    #: stopped; see :class:`~pcapkit.foundation.reassembly.data.data.Completion`.
    completed: 'Completion'
    #: Original packet identifier.
    id: 'DatagramID[_AT]'
    #: Packet numbers of the fragments that built this message.
    index: 'tuple[int, ...]'
    #: Message sequence number.
    message_seq: 'int'
    #: Handshake message type.
    msg_type: 'Enum_HandshakeType'
    #: Total message length, as declared by its fragments.
    length: 'int'
    #: Reassembled message body, undecoded;
    #: :func:`~pcapkit.foundation.analysis.dtls_handshake` decodes it.
    body: 'bytes | tuple[bytes, ...]'

    if TYPE_CHECKING:
        def __init__(self, completed: 'Completion', id: 'DatagramID[_AT]', index: 'tuple[int, ...]', message_seq: 'int', msg_type: 'Enum_HandshakeType', length: 'int', body: 'bytes | tuple[bytes, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class HoleDescriptor(Info):
    """Data model for :term:`DTLS <reasm.dtls.buffer>` hole descriptor.

    Both bounds are **inclusive** byte offsets into the reassembled message,
    so a hole covers ``last - first + 1`` octets. They never wrap and need no
    open-ended sentinel: every fragment declares the message's total
    :attr:`Fragment.length` (:rfc:`6347#section-4.2.3`), so it is known from
    the first fragment.

    """

    #: Offset of the first missing octet.
    first: 'int'
    #: Offset of the last missing octet, inclusive.
    last: 'int'

    if TYPE_CHECKING:
        def __init__(self, first: 'int', last: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Fragment(Info):
    """Data model for :term:`DTLS <reasm.dtls.buffer>` message-under-
    construction, one per :attr:`Packet.message_seq` buffered under one
    :data:`BufferID`."""

    #: Numbers of the packets merged into this fragment.
    ind: 'list[int]'
    #: Handshake message type -- read off the first-arriving fragment and
    #: trusted from there, same as :attr:`length`.
    msg_type: 'Enum_HandshakeType'
    #: Total message length, read off the first-arriving fragment.
    length: 'int'
    #: Reassembled payload, holes left zero-filled.
    raw: 'bytearray'
    #: Hole descriptor list; empty once the message is whole.
    hdl: 'list[HoleDescriptor]'

    if TYPE_CHECKING:
        def __init__(self, ind: 'list[int]', msg_type: 'Enum_HandshakeType', length: 'int', raw: 'bytearray', hdl: 'list[HoleDescriptor]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Buffer(Info):
    """Data model for :term:`DTLS <reasm.dtls.buffer>` buffer entry -- every
    handshake message being reassembled under one :data:`BufferID`,
    i.e. one UDP association at one epoch."""

    #: Messages under reconstruction, by :attr:`Packet.message_seq`. Several
    #: may be in flight at once: a ``Certificate``, a ``ServerKeyExchange``
    #: and a ``ServerHelloDone`` can each fragment independently in the same
    #: flight.
    msg: 'dict[int, Fragment]'
    #: Capture timestamp of the first fragment buffered under this buffer ID,
    #: in seconds since the Unix epoch. Recorded only: the buffer has no
    #: time-based deadline, so it is never expired by time.
    timestamp: 'float'

    if TYPE_CHECKING:
        def __init__(self, msg: 'dict[int, Fragment]', timestamp: 'float') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
