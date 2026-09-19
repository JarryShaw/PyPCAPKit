# -*- coding: utf-8 -*-
"""data models for IP reassembly"""

from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.foundation.reassembly.data.data import Completion, Deferred, DeferredPacket
from pcapkit.utilities.compat import Tuple

__all__ = [
    'Packet', 'DatagramID', 'Datagram', 'Buffer', 'BufferID',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Callable, Optional

    from typing_extensions import TypeAlias

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

_AT = TypeVar('_AT', 'IPv4Address', 'IPv6Address')

#: Buffer ID.
BufferID: 'TypeAlias' = Tuple[_AT, _AT, int, 'TransType']


@info_final
class Packet(Info, Generic[_AT]):
    """Data model for :term:`IPv4 <reasm.ipv4.packet>` and/or
    :term:`IPv6 <reasm.ipv6.packet>` packet representation.."""

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
    #: Capture timestamp of the fragment, in seconds since the Unix epoch. This
    #: is the *capture's* clock, not the host's: it is what drives the :rfc:`791`
    #: and :rfc:`8200#section-4.5` reassembly timeout, since an offline parser
    #: replaying a file has no other notion of time passing.
    timestamp: 'float'

    if TYPE_CHECKING:
        def __init__(self, bufid: 'tuple[_AT, _AT, int, TransType]', num: 'int', fo: 'int', ihl: 'int', mf: 'bool', tl: 'int', header: 'bytes', payload: 'bytearray', timestamp: 'float') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class DatagramID(Info, Generic[_AT]):
    """Data model for :term:`IPv4 <reasm.ipv4.datagram>` and/or
    :term:`IPv6 <reasm.ipv6.datagram>` original packet identifier."""

    #: Source address.
    src: '_AT'
    #: Destination address.
    dst: '_AT'
    #: IP protocol identifier.
    id: 'int'
    #: Payload protocol type.
    proto: 'TransType'

    if TYPE_CHECKING:
        def __init__(self, src: '_AT', dst: '_AT', id: 'int', proto: 'TransType') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Datagram(DeferredPacket, Info, Generic[_AT]):
    """Data model for :term:`IPv4 <reasm.ipv4.datagram>` and/or
    :term:`IPv6 <reasm.ipv6.datagram>` reassembled datagram."""

    #: Listing ``packet`` here is what makes :attr:`packet` lazy. :class:`Info`
    #: stores a field whose name is a *builtin* name under a mangled key and maps
    #: it back on the way out, so ``packet`` never lands in :attr:`__dict__`
    #: itself -- which routes reading it through :meth:`__getattr__`, where a
    #: :class:`Deferred` analysis can be run, while ``dict(datagram)``,
    #: :meth:`to_dict` and iteration still report the field under its own name.
    __additional__ = ['packet']

    #: How completely the datagram was reassembled, and why reassembly stopped.
    #: Only :attr:`Completion.COMPLETE` is truthy, so ``if datagram.completed:``
    #: still reads as it did while this was a :obj:`bool`; equality against
    #: :obj:`True` or :obj:`False` no longer holds.
    completed: 'Completion'
    #: Original packet identifier.
    id: 'DatagramID[_AT]'
    #: Packet numbers.
    index: 'tuple[int, ...]'
    #: Initial IP header.
    header: 'bytes'
    #: Reassembled IP payload.
    payload: 'bytes | tuple[bytes, ...]'
    #: Parsed IP payload. Analysed on first read, not at construction time; a
    #: :class:`Deferred` may be passed in its place, and reading this attribute
    #: then runs it and keeps the result.
    packet: 'Optional[Protocol]'
    #: Octet ranges, absolute into the reassembled payload and both
    #: **inclusive** -- the same convention as :attr:`Packet.fo` combined with
    #: its length -- on which two fragments disagreed, i.e. an arriving
    #: fragment overlapped octets already buffered but did not repeat them.
    #: Empty when the datagram never saw a contested octet.
    #:
    #: :rfc:`791` resolves the disagreement itself: "In the case that two or
    #: more fragments contain the same data either identically or through a
    #: partial overlap, this procedure will use the more recently arrived copy
    #: in the data buffer and datagram delivered." So :attr:`payload` always
    #: holds whichever fragment arrived *last* over a contested range -- the
    #: opposite resolution from TCP's first-write-wins
    #: (:rfc:`9293#section-3.10`) -- and this field is what lets a caller tell
    #: a clean datagram from a contested one, since a resolved conflict does
    #: not, on its own, leave a hole for ``completed`` to report.
    #:
    #: :attr:`Buffer.RCVBT <pcapkit.foundation.reassembly.data.ip.Buffer.RCVBT>`
    #: only records receipt in 8-octet blocks, coarser than the octet
    #: granularity a conflict needs. Every fragment but the last is required
    #: to be block-aligned (and :attr:`Packet.fo` is *always* a multiple of 8,
    #: being wire-encoded in 8-octet units), so the only block that can be
    #: partially real is the one holding the final fragment's own tail -- and
    #: a range reported here never extends past
    #: :attr:`Buffer.TDL <pcapkit.foundation.reassembly.data.ip.Buffer.TDL>`
    #: for exactly that reason, even though a whole ``RCVBT`` block straddling
    #: it reads as "received". See
    #: :meth:`IP._detect_conflicts <pcapkit.foundation.reassembly.ip.IP._detect_conflicts>`.
    conflict: 'tuple[tuple[int, int], ...]'

    if TYPE_CHECKING:
        # NOTE: one signature, not a pair of ``@overload``\\ s keyed on
        # ``completed``. There used to be two, correlating a complete datagram with
        # a ``bytes`` payload and a parsed ``packet``, and an incomplete one with a
        # tuple of fragments and ``packet=None``. That correlation does not hold:
        # under ``strict=False`` an *incomplete* datagram is reported as one
        # contiguous ``bytes`` with its holes zero-filled, and analysed, because
        # that is the payload buffer as it stands -- which is what
        # :func:`~pcapkit.interface.misc.follow_tcp_stream` reconstructs a stream
        # from. Overloads keyed on a literal cannot be selected from a ``completed``
        # computed at runtime anyway, so they only made the reassemblers' own calls
        # untypeable while promising a correlation the code does not keep.
        def __init__(self, completed: 'Completion', id: 'DatagramID[_AT]', index: 'tuple[int, ...]', header: 'bytes', payload: 'bytes | tuple[bytes, ...]', packet: 'Optional[Protocol | Deferred]', conflict: 'tuple[tuple[int, int], ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

@info_final
class Buffer(Info, Generic[_AT]):
    """Data model for :term:`IPv4 <reasm.ipv4.buffer>` and/or
    :term:`IPv6 <reasm.ipv6.buffer>` reassembly buffer entry."""

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
    #: Capture timestamp of the **first-arriving** fragment of this datagram, in
    #: seconds since the Unix epoch. This is the origin of the reassembly timer:
    #: :rfc:`8200#section-4.5` counts its 60 seconds "of the reception of the
    #: first-arriving fragment", so a later fragment does not extend the
    #: deadline and this field is never revised once set.
    timestamp: 'float'
    #: Octet ranges, absolute into :attr:`datagram` and both **inclusive**, on
    #: which an arriving fragment disagreed with bytes already placed there by
    #: an earlier one. Accumulated across every fragment merged into this
    #: buffer, in the order the conflicts were found; carried onto
    #: :attr:`Datagram.conflict <pcapkit.foundation.reassembly.data.ip.Datagram.conflict>`
    #: verbatim when the buffer is submitted.
    conflict: 'list[tuple[int, int]]'

    if TYPE_CHECKING:
        def __init__(self, TDL: 'int', RCVBT: 'bytearray', index: 'list[int]', header: 'bytes', datagram: 'bytearray', timestamp: 'float', conflict: 'list[tuple[int, int]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin
