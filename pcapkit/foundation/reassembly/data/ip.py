# -*- coding: utf-8 -*-
"""data models for IP reassembly"""

from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.foundation.reassembly.data.data import Deferred
from pcapkit.utilities.compat import Tuple

__all__ = [
    'Packet', 'DatagramID', 'Datagram', 'Buffer', 'BufferID',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Callable, Optional, overload

    from typing_extensions import Literal, TypeAlias

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

    if TYPE_CHECKING:
        def __init__(self, bufid: 'tuple[_AT, _AT, int, TransType]', num: 'int', fo: 'int', ihl: 'int', mf: 'bool', tl: 'int', header: 'bytes', payload: 'bytearray') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


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
class Datagram(Info, Generic[_AT]):
    """Data model for :term:`IPv4 <reasm.ipv4.datagram>` and/or
    :term:`IPv6 <reasm.ipv6.datagram>` reassembled datagram."""

    #: Listing ``packet`` here is what makes :attr:`packet` lazy. :class:`Info`
    #: stores a field whose name is a *builtin* name under a mangled key and maps
    #: it back on the way out, so ``packet`` never lands in :attr:`__dict__`
    #: itself -- which routes reading it through :meth:`__getattr__`, where a
    #: :class:`Deferred` analysis can be run, while ``dict(datagram)``,
    #: :meth:`to_dict` and iteration still report the field under its own name.
    __additional__ = ['packet']

    #: Completed flag.
    completed: 'bool'
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

    if TYPE_CHECKING:
        @overload  #pylint: disable=used-before-assignment
        def __init__(self, completed: 'Literal[True]', id: 'DatagramID[_AT]', index: 'tuple[int, ...]', header: 'bytes', payload: 'bytes', packet: 'Protocol | Deferred') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

        @overload
        def __init__(self, completed: 'Literal[False]', id: 'DatagramID[_AT]', index: 'tuple[int, ...]', header: 'bytes', payload: 'tuple[bytes, ...]', packet: 'None') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

        def __init__(self, completed: 'bool', id: 'DatagramID[_AT]', index: 'tuple[int, ...]', header: 'bytes', payload: 'bytes | tuple[bytes, ...]', packet: 'Optional[Protocol | Deferred]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

    def __analyse__(self) -> 'Optional[Protocol]':
        """Resolve a deferred analysis, at most once.

        Returns:
            Parsed IP payload, or :data:`None` for an incomplete datagram.

        """
        key = self.__map__.get('packet', 'packet')
        value = self.__dict__[key]
        if isinstance(value, Deferred):
            value = value()
            self.__dict__[key] = value
        return value

    def __getattr__(self, name: 'str') -> 'Any':
        # NOTE: reached only for names absent from ``__dict__``, which ``packet``
        # always is -- see ``__additional__`` above. Everything else has to raise,
        # or a typo would silently answer with a parsed payload.
        if name != 'packet':
            raise AttributeError(f'{type(self).__name__!r} object has no attribute {name!r}')
        return self.__analyse__()

    def __getitem__(self, name: 'str') -> 'Any':
        if name == 'packet':
            return self.__analyse__()
        return super().__getitem__(name)

    def __contains__(self, name: 'object') -> 'bool':
        # NOTE: ``Mapping.__contains__`` answers by fetching the value, which
        # would run the deferred analysis merely to decide that the field exists.
        # ``packet`` is a declared field, so it is always there.
        return name == 'packet' or super().__contains__(name)

    def __str__(self) -> 'str':
        self.__analyse__()
        return super().__str__()

    def __repr__(self) -> 'str':
        self.__analyse__()
        return super().__repr__()

    def to_dict(self) -> 'dict[str, Any]':
        """Convert :class:`Datagram` into :obj:`dict`.

        Returns:
            The datagram's fields, with ``packet`` analysed if it had not been
            read yet -- a :obj:`dict` holding a :class:`Deferred` would leak an
            implementation detail into what is meant to be plain data.

        """
        self.__analyse__()
        return super().to_dict()


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

    if TYPE_CHECKING:
        def __init__(self, TDL: 'int', RCVBT: 'bytearray', index: 'list[int]', header: 'bytes', datagram: 'bytearray') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin
