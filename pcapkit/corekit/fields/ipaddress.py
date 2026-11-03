# -*- coding: utf-8 -*-
"""IP address field class

.. versionchanged:: 1.5.0

   Every field here rejects a :obj:`bool` with
   :exc:`~pcapkit.utilities.exceptions.FieldValueError`, where an IPv4 field
   packed :obj:`True` and :obj:`False` as ``0.0.0.1`` and ``0.0.0.0``
   (:issue:`491`).

.. versionremoved:: 1.6.0

   ``pcapkit.corekit.fields.ipaddress.parse_ip_address`` and
   ``pcapkit.corekit.fields.ipaddress._reject_bool``, now
   :func:`pcapkit.corekit.schema.ipaddress.parse_ip_address` and
   :func:`pcapkit.corekit.schema.ipaddress._reject_bool` (:issue:`2674`).

"""

import abc
import ipaddress
import re
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.corekit.fields.field import Field
from pcapkit.corekit.schema.ipaddress import _reject_bool, _reraise_as_field_value_error
from pcapkit.corekit.sentinels import NO_VALUE
from pcapkit.utilities.exceptions import FieldValueError

__all__ = [
    'IPv4AddressField', 'IPv6AddressField',
    'IPv4InterfaceField', 'IPv6InterfaceField',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
    from typing import Any, Callable, Optional

    from typing_extensions import Literal, Self

    from pcapkit.corekit.sentinels import NoValueType


_T = TypeVar('_T', 'IPv4Address', 'IPv6Address',
             'IPv4Interface', 'IPv6Interface')
_AT = TypeVar('_AT', 'IPv4Address', 'IPv6Address')
_IT = TypeVar('_IT', 'IPv4Interface', 'IPv6Interface')


class _IPField(Field[_T], Generic[_T]):
    """Internal IP related value for protocol fields.

    Args:
        length: Field size (in bytes).
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    @property
    @abc.abstractmethod
    def version(self) -> 'int':
        """IP version number."""


class _IPAddressField(_IPField[_AT]):
    """Internal IP address value for protocol fields.

    Args:
        length: Field size (in bytes).
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    def pre_process(self, value: '_AT | bytes | int | str', packet: 'dict[str, Any]') -> 'bytes':
        """Process field value before packing.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If ``value`` is a :obj:`bool` (cf.
                :func:`~pcapkit.corekit.schema.ipaddress._reject_bool`), is not a
                valid IP address, or is the wrong IP version for this field.

        """
        _reject_bool(value, 'invalid IP address')

        if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            ip = value  # type: IPv4Address | IPv6Address
        else:
            with _reraise_as_field_value_error('invalid IP address'):
                ip = ipaddress.ip_address(value)

        if ip.version != self.version:
            raise FieldValueError(f'IP version mismatch: {ip.version} != {self.version}')
        return ip.packed

    def post_process(self, value: 'bytes', packet: 'dict[str, Any]') -> '_AT':
        """Process field value after parsing (unpacking).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If ``value`` is the wrong IP version for this
                field. ``value`` cannot actually fail the underlying
                :func:`ipaddress.ip_address` conversion here -- it is always
                exactly 4 or 16 octets, fixed by this field's length, and any
                such octet string is a valid address -- but the conversion is
                still wrapped for consistency with the rest of this module.

        """
        with _reraise_as_field_value_error('invalid IP address'):
            val = ipaddress.ip_address(value)
        if val.version != self.version:
            raise FieldValueError(f'IP version mismatch: {val.version} != {self.version}')
        return val  # type: ignore[return-value]


class IPv4AddressField(_IPAddressField[ipaddress.IPv4Address]):
    """IPv4 address value for protocol fields.

    Args:
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    @property
    def version(self) -> 'Literal[4]':
        """IP version number."""
        return 4

    def __init__(self, default: 'IPv4Address | NoValueType' = NO_VALUE,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(4, default, callback)

        self._template = f'4s'


class IPv6AddressField(_IPAddressField[ipaddress.IPv6Address]):
    """IPv6 address value for protocol fields.

    Args:
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    @property
    def version(self) -> 'Literal[6]':
        """IP version number."""
        return 6

    def __init__(self, default: 'IPv6Address | NoValueType' = NO_VALUE,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(16, default, callback)

        self._template = f'16s'


class _IPInterfaceField(_IPField[_IT]):
    """Internal IP interface value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """


class _RawMaskIPv4Interface(ipaddress.IPv4Interface):
    """IPv4 interface whose mask is not a contiguous netmask.

    Args:
        address: Dotted address and mask, as ``'a.b.c.d/m.m.m.m'`` or
            ``'a.b.c.d/0xXXXXXXXX'``; either way the mask is read literally.

    :class:`ipaddress.IPv4Interface` can only hold a prefix length, so it
    reads a hostmask-shaped mask such as ``0.0.0.255`` as ``/24`` and rejects
    a mask such as ``255.0.255.0``. This class keeps the mask octets as given
    in :attr:`netmask`, so :meth:`IPv4InterfaceField.pre_process` writes them
    back unchanged.

    :class:`str`, :func:`repr` and :mod:`pickle` use the ``address/mask``
    form, which :meth:`IPv4InterfaceField.pre_process` packs back to the same
    octets. The mask is dotted, except when it is hostmask-shaped (ones, then
    zeros, read from the low bit): :func:`ipaddress.ip_interface` would read
    such a dotted mask as a hostmask, so it is written as eight hex digits
    instead, e.g. ``10.0.0.1/0x000000ff``. The stdlib rejects that hex form,
    so it never means anything else there.

    Equality and ordering use the mask too. An instance sorts as the stdlib
    sorts ``address/32``, then by mask, so the order stays total when mixed
    with :class:`ipaddress.IPv4Interface` values.

    Such a mask has no prefix length, so
    :attr:`~ipaddress.IPv4Interface.network`,
    :attr:`~ipaddress.IPv4Interface.with_prefixlen` and the prefix length all
    describe the address alone (``/32``); only :attr:`netmask`,
    :attr:`hostmask`, :attr:`~ipaddress.IPv4Interface.with_netmask` and
    :attr:`~ipaddress.IPv4Interface.with_hostmask` carry the mask.
    :attr:`~ipaddress.IPv4Interface.with_netmask` is always dotted, so it is
    not the round-trip form; :class:`str` is.

    """

    def __init__(self, address: 'str') -> 'None':
        addr, _, mask = address.partition('/')
        super().__init__(addr)
        #: Mask octets as given, which need not form a contiguous netmask.
        self.netmask = _parse_literal_mask(mask)

    @property
    def hostmask(self) -> 'IPv4Address':
        """Bitwise inverse of :attr:`netmask`."""
        return ipaddress.IPv4Address(int(self.netmask) ^ 0xFFFFFFFF)

    def __str__(self) -> 'str':
        if _is_hostmask(self.netmask):
            return f'{self.ip}/0x{int(self.netmask):08x}'
        return f'{self.ip}/{self.netmask}'

    def __eq__(self, other: 'object') -> 'bool':
        if not isinstance(other, ipaddress.IPv4Interface):
            return NotImplemented
        return self.ip == other.ip and self.netmask == other.netmask

    def __hash__(self) -> 'int':
        return hash((int(self.ip), int(self.netmask)))

    def __lt__(self, other: 'Any') -> 'bool':
        if not isinstance(other, ipaddress.IPv4Interface):
            return ipaddress.IPv4Interface.__lt__(self, other)
        return _interface_order(self) < _interface_order(other)

    def __le__(self, other: 'Any') -> 'bool':
        if not isinstance(other, ipaddress.IPv4Interface):
            return ipaddress.IPv4Interface.__le__(self, other)
        return _interface_order(self) <= _interface_order(other)

    def __gt__(self, other: 'Any') -> 'bool':
        if not isinstance(other, ipaddress.IPv4Interface):
            return ipaddress.IPv4Interface.__gt__(self, other)
        return _interface_order(self) > _interface_order(other)

    def __ge__(self, other: 'Any') -> 'bool':
        if not isinstance(other, ipaddress.IPv4Interface):
            return ipaddress.IPv4Interface.__ge__(self, other)
        return _interface_order(self) >= _interface_order(other)


def _is_netmask(mask: 'IPv4Address') -> 'bool':
    """Tell whether ``mask`` is a contiguous netmask (leading ones, then zeros).

    Args:
        mask: Dotted mask.

    Returns:
        :data:`True` for ``0.0.0.0`` through ``255.255.255.255`` with no gap
        in the ones, :data:`False` otherwise.

    """
    inverse = int(mask) ^ 0xFFFFFFFF
    return not inverse & (inverse + 1)


def _is_hostmask(mask: 'IPv4Address') -> 'bool':
    """Tell whether ``mask`` is hostmask-shaped (leading zeros, then ones).

    Args:
        mask: Dotted mask.

    Returns:
        :data:`True` when :func:`ipaddress.ip_interface` would accept the
        dotted ``mask`` as a hostmask, :data:`False` otherwise.

    """
    value = int(mask)
    return not value & (value + 1)


#: Hex spelling of a literal mask, as :class:`str` writes a hostmask-shaped one.
_HEX_MASK = re.compile(r'0[xX][0-9a-fA-F]{8}')


def _parse_literal_mask(text: 'str') -> 'IPv4Address':
    """Read a mask literally, from eight hex digits or a dotted quad.

    Args:
        text: ``0xXXXXXXXX`` or ``m.m.m.m``.

    Returns:
        The mask as given, never reinterpreted as a hostmask.

    Raises:
        ValueError: If ``text`` is neither form.

    """
    if _HEX_MASK.fullmatch(text) is not None:
        return ipaddress.IPv4Address(int(text, 16))
    return ipaddress.IPv4Address(text)


def _interface_from_mask(ip: 'IPv4Address', mask: 'IPv4Address') -> 'IPv4Interface':
    """Build the interface for an address and a literal mask.

    Args:
        ip: Interface address.
        mask: Mask, taken as given.

    Returns:
        A stdlib :class:`~ipaddress.IPv4Interface` when ``mask`` is a
        contiguous netmask, otherwise a :class:`_RawMaskIPv4Interface`.

    """
    if _is_netmask(mask):
        return ipaddress.IPv4Interface(f'{ip}/{mask}')
    return _RawMaskIPv4Interface(f'{ip}/{mask}')


def _literal_interface(value: 'str') -> 'Optional[IPv4Interface]':
    """Read an ``address/mask`` string with the mask taken literally.

    Args:
        value: Interface string that :func:`ipaddress.ip_interface` rejected.

    Returns:
        The interface, or :obj:`None` if ``value`` is not an IPv4 address
        followed by a dotted or ``0xXXXXXXXX`` mask.

    """
    addr, sep, mask = value.partition('/')
    if not sep or ('.' not in mask and _HEX_MASK.fullmatch(mask) is None):
        return None
    try:
        return _interface_from_mask(ipaddress.IPv4Address(addr), _parse_literal_mask(mask))
    except ValueError:
        return None


def _interface_order(value: 'IPv4Interface') -> 'tuple[int, int, int, int]':
    """Sort key for an IPv4 interface, consistent with ``==``.

    Args:
        value: IPv4 interface, either from the stdlib or a
            :class:`_RawMaskIPv4Interface`.

    Returns:
        The stdlib order (network address, netmask, address), with a third
        element that is ``0`` for a stdlib interface and ``1 + mask`` for a
        :class:`_RawMaskIPv4Interface`, whose stdlib network is
        ``address/32``.

    """
    if isinstance(value, _RawMaskIPv4Interface):
        return int(value.ip), 0xFFFFFFFF, 1 + int(value.netmask), int(value.ip)
    return int(value.network.network_address), int(value.network.netmask), 0, int(value.ip)


class IPv4InterfaceField(_IPInterfaceField[ipaddress.IPv4Interface]):
    """IPv4 interface value for protocol fields.

    Args:
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    .. versionchanged:: 1.5.0

       A mask that is not a contiguous netmask unpacks to an
       :class:`~ipaddress.IPv4Interface` subclass that keeps its four octets,
       where a hostmask-shaped one was read as a prefix length and any other
       raised (:issue:`1294`).

    """

    @property
    def version(self) -> 'Literal[4]':
        """IP version number."""
        return 4

    def __init__(self, default: 'IPv4Interface | NoValueType' = NO_VALUE,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(8, default, callback)

        self._template = f'8s'

    def pre_process(self, value: 'IPv4Interface | bytes | int | str', packet: 'dict[str, Any]') -> 'bytes':
        """Process field value before packing.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If ``value`` is a :obj:`bool` (cf.
                :func:`~pcapkit.corekit.schema.ipaddress._reject_bool`), is not a
                valid IP interface, or is the
                wrong IP version for this field.

        Notes:
            A string means what :func:`ipaddress.ip_interface` says it
            means, so ``'10.0.0.1/0.0.0.255'`` is the hostmask spelling of
            ``/24``. Only a string the stdlib rejects is read with its mask
            taken literally: a dotted mask that is neither a netmask nor a
            hostmask, such as ``'10.0.0.1/255.0.255.0'``, or eight hex
            digits, such as ``'10.0.0.1/0x000000ff'``. Those are the forms
            :class:`str` gives a :class:`_RawMaskIPv4Interface`.

        """
        _reject_bool(value, 'invalid IP interface')

        if isinstance(value, ipaddress.IPv4Interface):
            val = value
        else:
            try:
                parsed = ipaddress.ip_interface(value)  # type: IPv4Interface | IPv6Interface
            except ValueError as error:
                literal = _literal_interface(value) if isinstance(value, str) else None
                if literal is None:
                    raise FieldValueError(f'invalid IP interface: {error}') from error
                parsed = literal
            if not isinstance(parsed, ipaddress.IPv4Interface):
                raise FieldValueError(f'IP version mismatch: {parsed.version} != {self.version}')
            val = parsed

        ip = val.ip
        mask = val.netmask
        return ip.packed + mask.packed

    def post_process(self, value: 'bytes', packet: 'dict[str, Any]') -> 'IPv4Interface':
        """Process field value after parsing (unpacking).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If the resulting interface is the wrong IP
                version for this field. The eight octets cannot actually fail
                to convert here -- they are always exactly 8 octets, fixed by
                this field's length, any four octets are a valid address, and
                a mask that is not a netmask is kept as given -- but the
                conversion is still wrapped for consistency with the rest of
                this module.

        Notes:
            The trailing four octets are a dotted netmask, as written by
            :meth:`pre_process` -- not a prefix length as in
            :meth:`IPv6InterfaceField.post_process`. When they are not a
            contiguous netmask, the value is a :class:`_RawMaskIPv4Interface`
            that keeps them as given, rather than an interface the stdlib
            would reinterpret (``0.0.0.255`` as the hostmask of ``/24``).

        """
        with _reraise_as_field_value_error('invalid IPv4 address'):
            ip = ipaddress.IPv4Address(value[:4])
            mask = ipaddress.IPv4Address(value[4:])

        with _reraise_as_field_value_error('invalid IPv4 interface'):
            val = _interface_from_mask(ip, mask)
        if not isinstance(val, ipaddress.IPv4Interface):
            raise FieldValueError(f'IP version mismatch: {val.version} != {self.version}')
        return val


class IPv6InterfaceField(_IPInterfaceField[ipaddress.IPv6Interface]):
    """IPv6 interface value for protocol fields.

    Args:
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    @property
    def version(self) -> 'Literal[6]':
        """IP version number."""
        return 6

    def __init__(self, default: 'IPv6Interface | NoValueType' = NO_VALUE,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(17, default, callback)

        self._template = f'17s'

    def pre_process(self, value: 'IPv6Interface | bytes | int | str', packet: 'dict[str, Any]') -> 'bytes':
        """Process field value before packing.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If ``value`` is a :obj:`bool` (cf.
                :func:`~pcapkit.corekit.schema.ipaddress._reject_bool`), is not a
                valid IP interface, or is the
                wrong IP version for this field.

        """
        _reject_bool(value, 'invalid IP interface')

        if isinstance(value, ipaddress.IPv6Interface):
            val = value
        else:
            with _reraise_as_field_value_error('invalid IP interface'):
                parsed = ipaddress.ip_interface(value)
            if not isinstance(parsed, ipaddress.IPv6Interface):
                raise FieldValueError(f'IP version mismatch: {parsed.version} != {self.version}')
            val = parsed

        ip = val.ip
        prefixlen = cast('int', val._prefixlen)  # type: ignore[attr-defined] # pylint: disable=protected-access
        return ip.packed + prefixlen.to_bytes(1, 'big')

    def post_process(self, value: 'bytes', packet: 'dict[str, Any]') -> 'IPv6Interface':
        """Process field value after parsing (unpacking).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If the trailing octet is not a valid IPv6 prefix
                length, i.e. greater than 128, or if the resulting interface
                is the wrong IP version for this field. Neither the leading
                sixteen octets nor the final :func:`ipaddress.ip_interface`
                call can actually fail here -- the former is always exactly
                16 octets, fixed by this field's length, and any such octet
                string is a valid address; the latter is only ever reached
                once the prefix length has already been checked above, and
                any prefix length in ``0..128`` is valid. Both conversions
                are still wrapped for consistency with the rest of this
                module.

        Notes:
            The trailing octet is the prefix length as a binary integer, as
            written by :meth:`pre_process` -- not a dotted netmask as in
            :meth:`IPv4InterfaceField.post_process`.

        """
        with _reraise_as_field_value_error('invalid IPv6 address'):
            ip = ipaddress.IPv6Address(value[:16])
        prefixlen = value[16]

        if prefixlen > 128:
            raise FieldValueError(f'invalid IPv6 prefix length: {prefixlen}')

        with _reraise_as_field_value_error('invalid IPv6 interface'):
            val = ipaddress.ip_interface(f'{ip}/{prefixlen}')
        if not isinstance(val, ipaddress.IPv6Interface):
            raise FieldValueError(f'IP version mismatch: {val.version} != {self.version}')
        return val
