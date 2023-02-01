# -*- coding: utf-8 -*-
"""numerical field class"""

import enum
from typing import TYPE_CHECKING, cast

from pcapkit.corekit.fields.field import Field
from pcapkit.utilities.exceptions import IntError

__all__ = [
    'NumberField',
    'IntField', 'UIntField',
    'ShortField', 'UShortField',
    'LongField', 'ULongField',
    'ByteField', 'UByteField',
    'EnumField',
]

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal


class NumberField(Field):
    """Numerical value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.
        size: field size (in bytes).
        signed: whether the field is signed.
        byteorder: field byte order.

    """

    __length__ = None  # type: Optional[int]
    __template__ = None  # type: Optional[str]
    __signed__ = None  # type: Optional[bool]

    def __init__(self, name: 'str', length: 'Optional[int]' = None, default: 'Any' = None,
                 signed: 'bool' = False, byteorder: 'Literal["little", "big"]' = 'big') -> 'None':
        if length is None:
            if self.__length__ is None:
                raise IntError(f'Field {name} has no length.')
            length = self.__length__
        super().__init__(name, length, default)

        self._signed = signed if self.__signed__ is None else self.__signed__
        self._byteorder = byteorder
        self._need_process = False

        endian = '>' if byteorder == 'big' else '<'
        if self.__template__ is not None:
            struct_fmt = self.__template__
        else:
            struct_fmt = self.build_template(length, signed)
        self._template = f'{endian}{struct_fmt}'

    def build_template(self, length: 'int', signed: 'bool') -> 'str':
        """Build template for field.

        Arguments:
            length: field size (in bytes)

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

    def pre_process(self, value: 'int') -> 'int | bytes':
        """Process field value before construction (packing).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        if not self._need_process:
            return value
        return value.to_bytes(
            self._length, self._byteorder, signed=self._signed
        )

    def post_process(self, value: 'int | bytes') -> 'int':
        """Process field value after parsing (unpacked).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        if not self._need_process:
            return cast('int', value)
        return int.from_bytes(
            cast('bytes', value), self._byteorder, signed=self._signed
        )


class IntField(NumberField):
    """Integer value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.

    """

    __length__ = 4
    __template__ = 'i'
    __signed__ = True


class UIntField(NumberField):
    """Unsigned integer value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.

    """

    __length__ = 4
    __template__ = 'I'
    __signed__ = False


class ShortField(NumberField):
    """Short integer value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.

    """

    __length__ = 2
    __template__ = 'h'
    __signed__ = True


class UShortField(NumberField):
    """Unsigned short integer value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.

    """

    __length__ = 2
    __template__ = 'H'
    __signed__ = False


class LongField(NumberField):
    """Long integer value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.

    """

    __length__ = 8
    __template__ = 'q'
    __signed__ = True


class ULongField(NumberField):
    """Unsigned long integer value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.

    """

    __length__ = 8
    __template__ = 'Q'
    __signed__ = False


class ByteField(NumberField):
    """Byte value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.

    """

    __length__ = 1
    __template__ = 'b'
    __signed__ = True


class UByteField(NumberField):
    """Unsigned byte value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.

    """

    __length__ = 1
    __template__ = 'B'
    __signed__ = False


class EnumField(NumberField):
    """Enumerated value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.
        signed: whether the field is signed.
        byteorder: field byte order.
        namespace: field namespace (a :class:`enum.IntEnum` class).

    """

    def __init__(self, name: 'str', length: 'int', default: 'Any' = None,
                 signed: 'bool' = False, byteorder: 'Literal["little", "big"]' = 'big',
                 namespace: 'Optional[Type[StdlibEnum] | Type[AenumEnum]]' = None) -> 'None':
        super().__init__(name, length, default, signed, byteorder)

        self._namespace = namespace

    def pre_process(self, value: 'StdlibEnum | AenumEnum') -> 'int | bytes':
        """Process field value before construction (packing).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        return super().pre_process(value.value)

    def post_process(self, value: 'int | bytes') -> 'StdlibEnum | AenumEnum':
        """Process field value after parsing (unpacked).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        value = super().post_process(value)
        if self._namespace is None:
            unknown = enum.IntEnum('<unknown>', {
                '<unassigned>': value,
            }, module='pcapkit.const', qualname='pcapkit.const.<unknown>')
            return getattr(unknown, '<unassigned>')
        return self._namespace(value)
