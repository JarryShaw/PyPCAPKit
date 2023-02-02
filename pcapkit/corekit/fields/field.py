# -*- coding: utf-8 -*-
"""base field class"""

import abc
import struct
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.utilities.exceptions import NoDefaultValue

__all__ = ['Field']

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

_T = TypeVar('_T')


class _Field(Generic[_T], metaclass=abc.ABCMeta):
    """Internal base class for protocol fields."""

    if TYPE_CHECKING:
        _default: Optional[_T]

    @property
    @abc.abstractmethod
    def name(self) -> 'str':
        """Field name."""

    @property
    def default(self) -> 'Optional[_T]':
        """Field default value."""
        return None

    @default.setter
    def default(self, value: '_T') -> 'None':
        """Set field default value."""
        self._default = value

    @property
    @abc.abstractmethod
    def template(self) -> 'str':
        """Field template."""

    @property
    def length(self) -> 'int':
        """Field size."""
        return struct.calcsize(self.template)

    def __call__(self, packet: 'dict[str, Any]') -> 'None':
        """Update field attributes.

        Arguments:
            packet: packet data.

        """

    def pre_process(self, value: '_T', packet: 'dict[str, Any]') -> 'Any':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: field value.
            packet: packet data.

        Returns:
            Processed field value.

        """
        return cast('Any', value)

    def pack(self, value: 'Optional[_T]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: field value.
            packet: packet data.

        Returns:
            Packed field value.

        """
        if value is None:
            if self._default is None:
                raise NoDefaultValue(f'Field {self.name} has no default value.')
            value = self._default

        pre_processed = self.pre_process(value, packet)
        return struct.pack(self.template, pre_processed)

    def post_process(self, value: 'Any', packet: 'dict[str, Any]') -> '_T':  # pylint: disable=unused-argument
        """Process field value after parsing (unpacking).

        Args:
            value: field value.
            packet: packet data.

        Returns:
            Processed field value.

        """
        return cast('_T', value)

    def unpack(self, buffer: 'bytes', packet: 'dict[str, Any]') -> '_T':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: field buffer.
            packet: packet data.

        Returns:
            Unpacked field value.

        """
        value = struct.unpack(self.template, buffer[:self.length])[0]
        return self.post_process(value, packet)


class Field(_Field[_T], Generic[_T]):
    """Base class for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: field default value, if any.

    """

    if TYPE_CHECKING:
        _template: 'str'

    @property
    def name(self) -> 'str':
        """Field name."""
        return self._name

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._template

    @property
    def length(self) -> 'int':
        """Field size."""
        return struct.calcsize(self.template)

    def __init__(self, name: 'str', length: 'int | Callable[[dict[str, Any]], int]',
                 default: 'Optional[_T]' = None) -> 'None':
        self._name = name
        self._default = default

        self._length_callback = None
        if not isinstance(length, int):
            self._length_callback, length = length, 1
        self._length = length

    def __call__(self, packet: 'dict[str, Any]') -> 'None':
        """Update field attributes."""
        if self._length_callback is None:
            return
        self._length = self._length_callback(packet)
