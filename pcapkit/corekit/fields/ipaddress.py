# -*- coding: utf-8 -*-
"""IP address field class"""

import abc
import ipaddress
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.corekit.fields.field import Field, NoValue
from pcapkit.utilities.exceptions import FieldValueError

__all__ = [
    'IPv4AddressField', 'IPv6AddressField',
    'IPv4InterfaceField', 'IPv6InterfaceField',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
    from typing import Any, Callable

    from typing_extensions import Literal, Self

    from pcapkit.corekit.fields.field import NoValueType


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

        """
        if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            ip = value  # type: IPv4Address | IPv6Address
        else:
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

        """
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

    def __init__(self, default: 'IPv4Address | NoValueType' = NoValue,
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

    def __init__(self, default: 'IPv6Address | NoValueType' = NoValue,
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


class IPv4InterfaceField(_IPInterfaceField[ipaddress.IPv4Interface]):
    """IPv4 interface value for protocol fields.

    Args:
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    @property
    def version(self) -> 'Literal[4]':
        """IP version number."""
        return 4

    def __init__(self, default: 'IPv4Interface | NoValueType' = NoValue,
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

        """
        if isinstance(value, ipaddress.IPv4Interface):
            val = value
        else:
            val = ipaddress.ip_interface(value)  # type: ignore[assignment]
            if val.version != self.version:
                raise FieldValueError(f'IP version mismatch: {val.version} != {self.version}')

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

        """
        ip = ipaddress.IPv4Address(value[:4])
        mask = ipaddress.IPv4Address(value[4:])

        val = ipaddress.ip_interface(f'{ip}/{mask}')
        if val.version != self.version:
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

    def __init__(self, default: 'IPv6Interface | NoValueType' = NoValue,
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

        """
        if isinstance(value, ipaddress.IPv6Interface):
            val = value
        else:
            val = ipaddress.ip_interface(value)  # type: ignore[assignment]
            if val.version != self.version:
                raise FieldValueError(f'IP version mismatch: {val.version} != {self.version}')

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

        """
        ip = ipaddress.IPv6Address(value[:16])
        mask = int(value[16:])

        val = ipaddress.ip_interface(f'{ip}/{mask}')
        if val.version != self.version:
            raise FieldValueError(f'IP version mismatch: {val.version} != {self.version}')
        return val
