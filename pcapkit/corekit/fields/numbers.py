# -*- coding: utf-8 -*-
"""numerical field class"""

import copy
import enum
from typing import TYPE_CHECKING, Generic, TypeVar, cast

import aenum

from pcapkit.corekit.fields.field import Field, NoValue
from pcapkit.utilities.exceptions import IntError

__all__ = [
    'NumberField',
    'Int32Field', 'UInt32Field',
    'Int16Field', 'UInt16Field',
    'Int64Field', 'UInt64Field',
    'Int8Field', 'UInt8Field',
    'EnumField',
]

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Callable, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.corekit.fields.field import NoValueType

_T = TypeVar('_T', bound='int')


class NumberField(Field[int], Generic[_T]):
    """Numerical value for protocol fields.

    Args:
        length: field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.
        bit_length: field bit length.
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    """

    __length__ = None  # type: Optional[int]
    __template__ = None  # type: Optional[str]
    __signed__ = None  # type: Optional[bool]

    @property
    def bit_length(self) -> 'int':
        """Field bit length."""
        return self._bit_length

    def __init__(self, length: 'Optional[int | Callable[[dict[str, Any]], int]]' = None,
                 default: 'int | NoValueType' = NoValue, signed: 'bool' = False,
                 byteorder: 'Literal["little", "big"]' = 'big',
                 bit_length: 'Optional[int]' = None,
                 callback: 'Callable[[NumberField[_T], dict[str, Any]], None]' = lambda *_: None) -> 'None':
        if length is None:
            if self.__length__ is None:
                raise IntError(f'Field has no length.')
            length = self.__length__
        super().__init__(length, default, callback)  # type: ignore[arg-type]

        if bit_length is None:
            bit_length = self._length * 8
        self._bit_length = bit_length
        self._bit_mask = (1 << bit_length) - 1

        self._signed = signed if self.__signed__ is None else self.__signed__
        self._byteorder = byteorder
        self._need_process = False

        endian = '>' if byteorder == 'big' else '<'
        if self.__template__ is not None:
            struct_fmt = self.__template__
        else:
            struct_fmt = self.build_template(self._length, signed)
        self._template = f'{endian}{struct_fmt}'

    def __call__(self, packet: 'dict[str, Any]') -> 'NumberField':
        """Update field attributes."""
        new_self = copy.copy(self)
        new_self._callback(self, packet)

        endian = '>' if new_self._byteorder == 'big' else '<'
        struct_fmt = new_self.build_template(new_self._length, new_self._signed)

        new_self._template = f'{endian}{struct_fmt}'
        return new_self

    def build_template(self, length: 'int', signed: 'bool') -> 'str':
        """Build template for field.

        Arguments:
            length: field size (in bytes)
            signed: whether the field is signed

        Returns:
            Template for field.

        """
        if length == 8:       # unpack to 8-byte integer (long long)
            struct_fmt = 'q' if signed else 'Q'
        elif length == 4:     # unpack to 4-byte integer (int / long)
            struct_fmt = 'i' if signed else 'I'
        elif length == 2:     # unpack to 2-byte integer (short)
            struct_fmt = 'h' if signed else 'H'
        elif length == 1:     # unpack to 1-byte integer (char)
            struct_fmt = 'b' if signed else 'B'
        else:                 # do not unpack
            struct_fmt = f'{length}s'
            self._need_process = True
        return struct_fmt

    def pre_process(self, value: 'int', packet: 'dict[str, Any]') -> 'int | bytes':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: field value.
            packet: packet data.

        Returns:
            Processed field value.

        """
        value = value & self._bit_mask
        if not self._need_process:
            return value
        return value.to_bytes(
            self._length, self._byteorder, signed=self._signed
        )

    def post_process(self, value: 'int | bytes', packet: 'dict[str, Any]') -> 'int':  # pylint: disable=unused-argument
        """Process field value after parsing (unpacked).

        Args:
            value: field value.
            packet: packet data.

        Returns:
            Processed field value.

        """
        if not self._need_process:
            return cast('int', value) & self._bit_mask
        return int.from_bytes(
            cast('bytes', value), self._byteorder, signed=self._signed
        ) & self._bit_mask


class Int32Field(NumberField):
    """Integer value for protocol fields.

    Args:
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.
        bit_length: field bit length.
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    """

    __length__ = 4
    __template__ = 'i'
    __signed__ = True


class UInt32Field(NumberField):
    """Unsigned integer value for protocol fields.

    Args:
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.
        bit_length: field bit length.
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    """

    __length__ = 4
    __template__ = 'I'
    __signed__ = False


class Int16Field(NumberField):
    """Short integer value for protocol fields.

    Args:
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.
        bit_length: field bit length.
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    """

    __length__ = 2
    __template__ = 'h'
    __signed__ = True


class UInt16Field(NumberField):
    """Unsigned short integer value for protocol fields.

    Args:
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.
        bit_length: field bit length.
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    """

    __length__ = 2
    __template__ = 'H'
    __signed__ = False


class Int64Field(NumberField):
    """Long integer value for protocol fields.

    Args:
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.
        bit_length: field bit length.
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    """

    __length__ = 8
    __template__ = 'q'
    __signed__ = True


class UInt64Field(NumberField):
    """Unsigned long integer value for protocol fields.

    Args:
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.
        bit_length: field bit length.
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    """

    __length__ = 8
    __template__ = 'Q'
    __signed__ = False


class Int8Field(NumberField):
    """Byte value for protocol fields.

    Args:
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.
        bit_length: field bit length.
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    """

    __length__ = 1
    __template__ = 'b'
    __signed__ = True


class UInt8Field(NumberField):
    """Unsigned byte value for protocol fields.

    Args:
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.
        bit_length: field bit length.
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    """

    __length__ = 1
    __template__ = 'B'
    __signed__ = False


class EnumField(NumberField[enum.IntEnum | aenum.IntEnum]):
    """Enumerated value for protocol fields.

    Args:
        length: field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.
        bit_length: field bit length.
        namespace: field namespace (a :class:`enum.IntEnum` class).
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    """

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]',
                 default: 'StdlibEnum | AenumEnum | NoValueType' = NoValue, signed: 'bool' = False,
                 byteorder: 'Literal["little", "big"]' = 'big',
                 bit_length: 'Optional[int]' = None,
                 namespace: 'Optional[Type[StdlibEnum] | Type[AenumEnum]]' = None,
                 callback: 'Callable[[EnumField, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(length, default, signed, byteorder, bit_length, callback)  # type: ignore[arg-type]

        self._namespace = namespace

    def post_process(self, value: 'int | bytes', packet: 'dict[str, Any]') -> 'StdlibEnum | AenumEnum':
        """Process field value after parsing (unpacked).

        Args:
            value: field value.
            packet: packet data.

        Returns:
            Processed field value.

        """
        value = super().post_process(value, packet)
        if self._namespace is None:
            unknown = enum.IntEnum('<unknown>', {
                '<unassigned>': value,
            }, module='pcapkit.const', qualname='pcapkit.const.<unknown>')
            return getattr(unknown, '<unassigned>')
        return self._namespace(value)
