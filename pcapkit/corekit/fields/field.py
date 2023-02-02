# -*- coding: utf-8 -*-
"""base field class"""

import abc
import struct
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.utilities.exceptions import NoDefaultValue

__all__ = ['Field']

if TYPE_CHECKING:
    from typing import Optional

_P = TypeVar('_P', 'int', 'bytes')
_T = TypeVar('_T')


class _Field(Generic[_P, _T], metaclass=abc.ABCMeta):
    """Internal base class for protocol fields."""

    @property
    @abc.abstractmethod
    def name(self) -> 'str':
        """Field name."""

    @property
    @abc.abstractmethod
    def default(self) -> '_T':
        """Field default value."""

    @property
    @abc.abstractmethod
    def template(self) -> 'str':
        """Field template."""

    @property
    @abc.abstractmethod
    def length(self) -> 'int':
        """Field size."""

    @abc.abstractmethod
    def pack(self, value: '_T') -> 'bytes':
        """Pack field value into :obj:`bytes`."""

    @abc.abstractmethod
    def unpack(self, buffer: 'bytes') -> '_T':
        """Unpack field value from :obj:`bytes`."""


class Field(_Field[_P, _T], Generic[_P, _T]):
    """Base class for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.

    """

    if TYPE_CHECKING:
        _template: 'str'

    @property
    def name(self) -> 'str':
        """Field name."""
        return self._name

    @property
    def default(self) -> '_T':
        """Field default value."""
        if self._default is None:
            raise NoDefaultValue(f'Field {self._name} has no default value.')
        return self._default

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._template

    @property
    def length(self) -> 'int':
        """Field size."""
        return struct.calcsize(self.template)

    def __init__(self, name: 'str', length: 'int', default: 'Optional[_T]' = None) -> 'None':
        self._name = name
        self._length = length
        self._default = default

    def pre_process(self, value: '_T') -> '_P':
        """Process field value before construction (packing).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        return cast('_P', value)

    def pack(self, value: '_T') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Arguments:
            value: field value

        Returns:
            Packed field value.

        """
        temp = self.pre_process(value)
        return struct.pack(self.template, temp)

    def post_process(self, value: '_P') -> '_T':
        """Process field value after parsing (unpacked).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        return cast('_T', value)

    def unpack(self, buffer: 'bytes') -> '_T':
        """Unpack field value from :obj:`bytes`.

        Arguments:
            buffer: buffer to unpack

        Returns:
            Unpacked field value.

        """
        temp = struct.unpack(self.template, buffer)[0]
        return self.post_process(temp)
