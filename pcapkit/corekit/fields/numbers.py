# -*- coding: utf-8 -*-
"""numerical field class"""

import enum
from typing import TYPE_CHECKING, cast

from pcapkit.corekit.fields.field import Field

__all__ = [
    'NumberField',
    'EnumField',
]

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Callable, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal


class NumberField(Field):
    """Numerical value for protocol fields.

    Args:
        condition: field condition function (this function should return a bool
            value and accept the current packet :class:`pcapkit.corekit.infoclass.Info`
            as its only argument).
        size: field size (in bytes).
        signed: whether the field is signed.
        byteorder: field byte order.

    """

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._size

    @property
    def endian(self) -> 'Literal["little", "big"]':
        """Field byte order."""
        return self._byteorder

    def __init__(self, condition: 'Optional[Callable[..., bool]]' = None,
                 size: 'int' = 1, signed: 'bool' = False,
                 byteorder: 'Literal["little", "big"]' = 'big') -> 'None':
        super().__init__(condition)

        self._size = size
        self._signed = signed
        self._byteorder = byteorder  # type: Literal["little", "big"]
        self._need_process = False

        if size == 8:       # unpack to 8-byte integer (long long)
            struct_fmt = 'q' if signed else 'Q'
        elif size == 4:     # unpack to 4-byte integer (int / long)
            struct_fmt = 'i' if signed else 'I'
        elif size == 2:     # unpack to 2-byte integer (short)
            struct_fmt = 'h' if signed else 'H'
        elif size == 1:     # unpack to 1-byte integer (char)
            struct_fmt = 'b' if signed else 'B'
        else:               # do not unpack
            struct_fmt = f'{size}s'
            self._need_process = True
        self._template = struct_fmt

    def pre_process(self, value: 'int') -> 'int | bytes':
        """Process field value before construction (packing).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        if not self._need_process:
            return value
        return value.to_bytes(self._size, self._byteorder, signed=self._signed)

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


class EnumField(NumberField):
    """Enumerated value for protocol fields."""

    def __init__(self, condition: 'Optional[Callable[..., bool]]' = None,
                 size: 'int' = 1, signed: 'bool' = False,
                 byteorder: 'Literal["little", "big"]' = 'big',
                 namespace: 'Optional[Type[StdlibEnum] | Type[AenumEnum]]' = None) -> 'None':
        super().__init__(condition, size, signed, byteorder)

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
                '<unassigned>': enum.auto(),
            }, module='pcapkit.const', qualname='pcapkit.const.<unknown>')
            return getattr(unknown, '<unassigned>')
        return self._namespace(value)
