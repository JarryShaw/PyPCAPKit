# -*- coding: utf-8 -*-
"""data models for TLS record reassembly

.. versionadded:: 1.9.0

"""

from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.corekit.packet import DeferredPacket
from pcapkit.foundation.reassembly.data import Deferred
from pcapkit.utilities.compat import Tuple

__all__ = [
    'DatagramID', 'Datagram', 'Run', 'Buffer', 'BufferID',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional

    from typing_extensions import TypeAlias

    from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
    from pcapkit.foundation.reassembly.data import Completion
    from pcapkit.protocols.protocol import ProtocolBase

_AT = TypeVar('_AT', 'IPv4Address', 'IPv6Address')

#: Buffer ID -- one direction of a TCP connection, its source address and port
#: and its destination address and port, as for TCP reassembly.
BufferID: 'TypeAlias' = Tuple[_AT, int, _AT, int]


@info_final
class DatagramID(Info, Generic[_AT]):
    """Data model for :term:`TLS <reasm.tls.datagram>` original record identifier."""

    #: Source address and port.
    src: 'tuple[_AT, int]'
    #: Destination address and port.
    dst: 'tuple[_AT, int]'
    #: TCP sequence number of the record's first octet.
    seq: 'int'

    if TYPE_CHECKING:
        def __init__(self, src: 'tuple[_AT, int]', dst: 'tuple[_AT, int]', seq: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Datagram(DeferredPacket, Info, Generic[_AT]):
    """Data model for :term:`TLS <reasm.tls.datagram>` reassembled record."""

    #: Listing ``packet`` here is what makes :attr:`packet` lazy -- see
    #: :class:`~pcapkit.corekit.packet.DeferredPacket`.
    __additional__ = ['packet']
    #: Placeholder class :attr:`packet` may hold, for
    #: :class:`~pcapkit.corekit.packet.DeferredPacket` to resolve.
    __deferred__ = Deferred

    #: How completely the record was reassembled, and why reassembly stopped;
    #: see :class:`~pcapkit.foundation.reassembly.data.Completion`.
    completed: 'Completion'
    #: Original record identifier.
    id: 'DatagramID[_AT]'
    #: Numbers of the packets that carried the record's octets.
    index: 'tuple[int, ...]'
    #: Record content type.
    content_type: 'Enum_ContentType'
    #: Legacy record version.
    version: 'int'
    #: Fragment length the record header declares.
    length: 'int'
    #: Reassembled fragment, undecoded.
    fragment: 'bytes | tuple[bytes, ...]'
    #: Decoded record, as :func:`~pcapkit.foundation.analysis.tls.tls_record` returns
    #: it unless the reassembly's ``__protocol_type__`` names another protocol, whose
    #: ``analyze_record`` then decodes it. Decoded on first read, and :data:`None`
    #: for an incomplete record. A
    #: :class:`~pcapkit.foundation.reassembly.data.Deferred` may be passed in its
    #: place, and reading this attribute then runs it and keeps the result.
    packet: 'Optional[ProtocolBase]'

    if TYPE_CHECKING:
        def __init__(self, completed: 'Completion', id: 'DatagramID[_AT]', index: 'tuple[int, ...]', content_type: 'Enum_ContentType', version: 'int', length: 'int', fragment: 'bytes | tuple[bytes, ...]', packet: 'Optional[ProtocolBase | Deferred[tuple[Enum_ContentType, int]]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Run(Info):
    """Data model for :term:`TLS <reasm.tls.buffer>` run of contiguous octets held."""

    #: Unwrapped sequence number of the octet held in ``raw[0]``.
    first: 'int'
    #: Octets held, in sequence order.
    raw: 'bytearray'

    if TYPE_CHECKING:
        def __init__(self, first: 'int', raw: 'bytearray') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Buffer(Info):
    """Data model for :term:`TLS <reasm.tls.buffer>` buffer entry -- one direction
    of a TCP connection, followed from a record boundary."""

    #: Unwrapped sequence number of the next record's first octet. Sequence
    #: numbers here are read modulo ``2 ** 32`` relative to it, so a stream
    #: crossing ``2 ** 32`` continues past it.
    boundary: 'int'
    #: Octets held at or past :attr:`boundary`, in sequence order, none adjacent
    #: to or overlapping another.
    runs: 'list[Run]'
    #: Octets each packet added. Each entry is ``(num, first, stop)``, its number and
    #: the unwrapped sequence range, ``stop`` exclusive, in the order they arrived.
    ind: 'list[tuple[int, int, int]]'
    #: Unwrapped sequence number the stream ends at, once its FIN is seen.
    fin: 'Optional[int]'
    #: Whether the stream has ended, at its FIN or an RST, so that only a SYN
    #: opens it again.
    closed: 'bool'
    #: Capture timestamp of the first segment buffered under this buffer ID, in
    #: seconds since the Unix epoch. Origin of the reassembly timer, and never
    #: revised.
    timestamp: 'float'

    if TYPE_CHECKING:
        def __init__(self, boundary: 'int', runs: 'list[Run]', ind: 'list[tuple[int, int, int]]', fin: 'Optional[int]', closed: 'bool', timestamp: 'float') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
