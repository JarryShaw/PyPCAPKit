# -*- coding: utf-8 -*-
"""base field class"""

import abc
import struct
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from typing_extensions import final

from pcapkit.utilities.exceptions import NoDefaultValue

__all__ = ['Field']

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.schema.schema import Schema

_T = TypeVar('_T')


@final
class NoValueType:
    """Default value for fields."""

    def __bool__(self) -> 'Literal[False]':
        """Return :obj:`False`."""
        return False


#: Default value for :attr:`_Field.default`.
NoValue = NoValueType()


class _Field(Generic[_T], metaclass=abc.ABCMeta):
    """Internal base class for protocol fields."""

    if TYPE_CHECKING:
        _name: 'str'
        _default: '_T | NoValueType'

    @property
    def name(self) -> 'str':
        """Field name."""
        return self._name

    @name.setter
    def name(self, value: 'str') -> 'None':
        """Set field name."""
        self._name = value

    @property
    def default(self) -> '_T | NoValueType':
        """Field default value."""
        return self._default

    @default.setter
    def default(self, value: '_T | NoValueType') -> 'None':
        """Set field default value."""
        self._default = value

    @default.deleter
    def default(self) -> 'None':
        """Delete field default value."""
        self._default = NoValue

    @property
    def template(self) -> 'str':
        """Field template."""
        return '0s'

    @property
    def length(self) -> 'int':
        """Field size."""
        return struct.calcsize(self.template)

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return False

    def __call__(self, packet: 'dict[str, Any]') -> '_Field':
        """Update field attributes.

        Arguments:
            packet: packet data.

        """
        self._callback(packet)  # type: ignore[attr-defined]
        return self

    def __repr__(self) -> 'str':
        return f'<{self.__class__.__name__} {self.name}>'

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
            if self._default is NoValue:
                raise NoDefaultValue(f'Field {self.name} has no default value.')
            value = cast('_T', self._default)

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

    def unpack(self, buffer: 'bytes | Schema', packet: 'dict[str, Any]') -> '_T':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: field buffer.
            packet: packet data.

        Returns:
            Unpacked field value.

        """
        if not isinstance(buffer, bytes):
            buffer = buffer.pack()
        value = struct.unpack(self.template, buffer[:self.length].rjust(self.length, b'\x00'))[0]
        return self.post_process(value, packet)


class Field(_Field[_T], Generic[_T]):
    """Base class for protocol fields.

    Args:
        length: field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: field default value, if any.
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    """

    if TYPE_CHECKING:
        _template: 'str'

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._template

    @property
    def length(self) -> 'int':
        """Field size."""
        return struct.calcsize(self.template)

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]',
                 default: '_T | NoValueType' = NoValue,
                 callback: 'Callable[[Field[_T], dict[str, Any]], None]' = lambda *_: None) -> 'None':
        self._name = '<unknown>'
        self._default = default
        self._callback = callback

        self._length_callback = None
        if not isinstance(length, int):
            self._length_callback, length = length, 0
        self._length = length

    def __call__(self, packet: 'dict[str, Any]') -> 'Field':
        """Update field attributes."""
        self._callback(self, packet)
        if self._length_callback is not None:
            self._length = self._length_callback(packet)
        return self
