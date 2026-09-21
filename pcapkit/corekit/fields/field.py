# -*- coding: utf-8 -*-
"""base field class"""

import abc
import copy
import struct
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.utilities.compat import final
from pcapkit.utilities.exceptions import FieldValueError, NoDefaultValue

__all__ = ['Field']

if TYPE_CHECKING:
    from typing import IO, Any, Callable, Optional

    from typing_extensions import Literal, Self

    from pcapkit.protocols.schema.schema import Schema

_T = TypeVar('_T')


@final
class NoValueType:
    """Default value for fields."""

    def __bool__(self) -> 'Literal[False]':
        """Return :obj:`False`."""
        return False


#: NoValueType: Default value for :attr:`FieldBase.default`.
NoValue = NoValueType()


class FieldMeta(abc.ABCMeta, Generic[_T]):
    """Meta class to add dynamic support to :class:`FieldBase`.

    This meta class is used to generate necessary attributes for the
    :class:`FieldBase` class. It can be useful to reduce unnecessary
    registry calls and simplify the customisation process.

    """


class FieldBase(Generic[_T], metaclass=FieldMeta):
    """Internal base class for protocol fields.

    Important:
        A negative value of :attr:`~FieldBase.length` indicates that the field
        is variable-length (i.e., length unspecified) and thus
        :meth:`~FieldBase.pack` should be considerate of the template format
        and the actual value provided for packing.

    Args:
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    """

    if TYPE_CHECKING:
        _name: 'str'
        _template: 'str'
        _callback: 'Callable[[Self, dict[str, Any]], None]'

    # NOTE: Declared on the class, not only assigned in :meth:`__init__`, so that
    # :attr:`default` is answerable for every field. A field class is free to
    # replace :meth:`__init__` without chaining to this one -- as
    # :class:`~pcapkit.corekit.fields.collections.ListField` does, since a list of
    # fields takes no default value of its own -- and reading :attr:`default` off
    # one of those raised :exc:`AttributeError` for a private attribute rather
    # than reporting that the field declares no default. See #422.
    _default: '_T | NoValueType' = NoValue

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
        return self._template

    @property
    def length(self) -> 'int':
        """Field size."""
        return struct.calcsize(self.template)

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return False

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Arguments:
            packet: Packet data.

        Returns:
            Updated field instance.

        This method will return a new instance of :class:`FieldBase` instead of
        updating the current instance.

        """
        new_self = copy.copy(self)
        new_self._callback(new_self, packet)
        return new_self

    # NOTE: This method is created as a placeholder for the necessary attributes.
    def __init__(self, *args: 'Any', **kwargs: 'Any') -> 'None':
        if not hasattr(self, '_name'):
            self._name = f'<{type(self).__name__[:-5].lower()}>'

        self._default = NoValue
        self._template = '0s'
        self._callback = lambda *_: None

    def __copy__(self) -> 'Self':
        """Return a shallow copy of the field.

        Every field of every protocol is copied once per packet by
        :meth:`__call__`, which made the generic :func:`copy.copy` path -- via
        :meth:`object.__reduce_ex__` and :func:`copy._reconstruct` -- one of the
        costlier things an extraction did. This does what that path would have
        done, and only that: a new instance of the same class, its
        :attr:`~object.__dict__` shallow-updated from this one.

        Returns:
            A new field instance sharing this one's attribute values.

        """
        new_self = self.__class__.__new__(self.__class__)
        new_self.__dict__.update(self.__dict__)
        return new_self

    def __repr__(self) -> 'str':
        if not self.name.isidentifier():
            return f'<{self.__class__.__name__}>'
        return f'<{self.__class__.__name__} {self.name}>'

    def __set_name__(self, owner: 'Schema', name: 'str') -> 'None':
        """Set field name and update field list (if applicable).

        This method is to be called by the metaclass during class creation.
        It is used to set the field name and update the field list, i.e.,
        :attr:`Schema.__fields__ <pcapkit.protocols.schema.schema.Schema.__fields__>`
        mapping dictionary.

        """
        # Update field list (if applicable)
        if hasattr(owner, '__fields__'):
            owner.__fields__[name] = self

        # Set field name
        self.name = name

    def pre_process(self, value: '_T', packet: 'dict[str, Any]') -> 'Any':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        return cast('Any', value)

    def pack(self, value: 'Optional[_T]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

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
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        return cast('_T', value)

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_T':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        Raises:
            FieldValueError: If ``buffer`` contains fewer octets than a
                dynamically sized field declares.

        """
        # NOTE: ``length`` recomputes struct.calcsize() on every read, so the
        # three reads this method used to make were three calcsize() calls for
        # one value.
        length = self.length

        if not isinstance(buffer, bytes):
            buffer = buffer.read(length)
        buffer_length = len(buffer)
        # Fixed-width fields have historically left-padded a short read, and
        # callers rely on that while producing their own field-relative errors.
        # A callable length is different: it can be derived from the packet being
        # parsed, so padding to it must not allocate bytes that never arrived.
        if buffer_length < length and getattr(self, '_length_callback', None) is not None:
            raise FieldValueError(
                f'Field {self.name} requires {length} octets, but only '
                f'{buffer_length} are available.'
            )

        value = struct.unpack(self.template, buffer[:length].rjust(length, b'\x00'))[0]
        return self.post_process(value, packet)


class Field(FieldBase[_T], Generic[_T]):
    """Base class for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    if TYPE_CHECKING:
        _template: 'str'

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._template

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]',
                 default: '_T | NoValueType' = NoValue,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        #self._name = '<unknown>'
        if not hasattr(self, '_name'):
            self._name = f'<{type(self).__name__[:-5].lower()}>'

        self._default = default
        self._callback = callback

        self._length_callback = None
        if not isinstance(length, int):
            self._length_callback, length = length, -1
        self._length = length

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Args:
            packet: Packet data.

        Returns:
            New instance of :class:`Field`.

        This method will return a new instance of :class:`Field` instead of
        updating the current instance.

        """
        new_self = copy.copy(self)
        new_self._callback(new_self, packet)
        if new_self._length_callback is not None:
            new_self._length = new_self._length_callback(packet)
        return new_self
