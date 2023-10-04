# -*- coding: utf-8 -*-
"""miscellaneous field class"""

import copy
import io
from typing import TYPE_CHECKING, TypeVar, cast

from pcapkit.corekit.fields.field import FieldBase, NoValue
from pcapkit.utilities.exceptions import FieldError, NoDefaultValue

__all__ = [
    'ConditionalField', 'PayloadField',
    'SwitchField', 'ForwardMatchField',
    'NoValueField',
]

if TYPE_CHECKING:
    from typing import IO, Any, Callable, Optional, Type

    from typing_extensions import Self

    from pcapkit.corekit.fields.field import NoValueType
    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.schema import Schema

_TC = TypeVar('_TC')
_TS = TypeVar('_TS', bound='Schema')
_TP = TypeVar('_TP', bound='Protocol')
_TN = TypeVar('_TN', bound='NoValueType')


class NoValueField(FieldBase[_TN]):
    """Schema field for no value type (or :obj:`None`)."""

    _default = NoValue

    @property
    def template(self) -> 'str':
        """Field template."""
        return '0s'

    @property
    def length(self) -> 'int':
        """Field size."""
        return 0

    def pack(self, value: 'Optional[_TN]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        """
        return b''

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_TN':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        """
        return None  # type: ignore[return-value]


class ConditionalField(FieldBase[_TC]):
    """Conditional value for protocol fields.

    Args:
        field: Field instance.
        condition: Field condition function (this function should return a bool
            value and accept the current packet :class:`pcapkit.corekit.infoclass.Info`
            as its only argument).

    """

    @property
    def name(self) -> 'str':
        """Field name."""
        return self._field.name

    @name.setter
    def name(self, value: 'str') -> 'None':
        """Set field name."""
        self._field.name = value

    @property
    def default(self) -> '_TC | NoValueType':
        """Field default value."""
        return self._field.default

    @default.setter
    def default(self, value: '_TC | NoValueType') -> 'None':
        """Set field default value."""
        self._field.default = value

    @default.deleter
    def default(self) -> 'None':
        """Delete field default value."""
        self._field.default = NoValue

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._field.template

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._field.length

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return True

    @property
    def field(self) -> 'FieldBase[_TC]':
        """Field instance."""
        return self._field

    def __init__(self, field: 'FieldBase[_TC]',  # pylint: disable=super-init-not-called
                 condition: 'Callable[[dict[str, Any]], bool]') -> 'None':
        self._field = field  # type: FieldBase[_TC]
        self._condition = condition

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Arguments:
            packet: Packet data.

        Returns:
            Updated field instance.

        This method will return a new instance of :class:`ConditionalField`
        instead of updating the current instance.

        """
        new_self = copy.copy(self)
        if new_self._condition(packet):
            new_self._field = new_self._field(packet)
        return new_self

    def pre_process(self, value: '_TC', packet: 'dict[str, Any]') -> 'Any':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        return self._field.pre_process(value, packet)

    def pack(self, value: 'Optional[_TC]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        """
        if not self._condition(packet):
            return b''
        return self._field.pack(value, packet)

    def post_process(self, value: 'Any', packet: 'dict[str, Any]') -> '_TC':  # pylint: disable=unused-argument
        """Process field value after parsing (unpacking).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        return self._field.post_process(value, packet)

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_TC':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        """
        if not self._condition(packet):
            return self._field.default  # type: ignore[return-value]
        return self._field.unpack(buffer, packet)

    def test(self, packet: 'dict[str, Any]') -> 'bool':
        """Test field condition.

        Arguments:
            packet: Current packet.

        Returns:
            bool: Test result.

        """
        return self._condition(packet)


class PayloadField(FieldBase[_TP]):
    """Payload value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value.
        protocol: Payload protocol.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._template

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._length

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return True

    @property
    def protocol(self) -> 'Type[_TP]':
        """Payload protocol."""
        if self._protocol is None:
            from pcapkit.protocols.misc.raw import Raw  # type: ignore[unreachable] # pylint: disable=import-outside-top-level # isort:skip
            return Raw
        return self._protocol

    @protocol.setter
    def protocol(self, protocol: 'Type[_TP] | str') -> 'None':
        """Set payload protocol.

        Arguments:
            protocol: Payload protocol.

        """
        if isinstance(protocol, str):
            from pcapkit.protocols import __proto__  # pylint: disable=import-outside-top-level
            protocol = cast('Type[_TP]', __proto__.get(protocol))
        self._protocol = protocol

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]' = lambda _: -1,
                 default: '_TP | NoValueType | bytes' = NoValue,
                 protocol: 'Optional[Type[_TP]]' = None,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        #self._name = '<payload>'
        self._default = default  # type: ignore[assignment]
        self._protocol = protocol  # type: ignore[assignment]
        self._callback = callback

        self._length_callback = None
        if not isinstance(length, int):
            self._length_callback, length = length, -1
        self._length = length
        self._template = f'{self._length}s' if self._length >= 0 else '1024s'  # use a reasonable default

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Args:
            packet: Packet data.

        Returns:
            Updated field instance.

        This method will return a new instance of :class:`PayloadField`
        instead of updating the current instance.

        """
        new_self = copy.copy(self)
        new_self._callback(new_self, packet)
        if new_self._length_callback is not None:
            new_self._length = new_self._length_callback(packet)
            new_self._template = f'{new_self._length}s'
        return new_self

    def pack(self, value: 'Optional[_TP | Schema | bytes]', packet: 'dict[str, Any]') -> 'bytes':
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
            value = cast('_TP', self._default)

        from pcapkit.protocols.schema.schema import \
            Schema  # pylint: disable=import-outside-top-level
        if isinstance(value, bytes):
            return value
        if isinstance(value, Schema):
            return value.pack()
        return value.data  # type: ignore[union-attr]

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_TP':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        """
        if self._protocol is None:
            if isinstance(buffer, bytes):  # type: ignore[unreachable]
                return cast('_TP', buffer)
            return cast('_TP', buffer.read())

        if isinstance(buffer, bytes):
            file = io.BytesIO(buffer)  # type: IO[bytes]
        else:
            file = buffer

        length = self._length if self._length > 0 else None
        return self._protocol(file, length)  # type: ignore[abstract]


class SwitchField(FieldBase[_TC]):
    """Conditional type-switching field for protocol schema.

    Args:
        selector: Callable function to select field type, which should accept
            the current packet as its only argument and return a field instance.

    """

    @property
    def name(self) -> 'str':
        """Field name."""
        return self._field.name

    @name.setter
    def name(self, value: 'str') -> 'None':
        """Set field name."""
        self._field.name = value

    @property
    def default(self) -> '_TC | NoValueType':
        """Field default value."""
        return self._field.default

    @default.setter
    def default(self, value: '_TC | NoValueType') -> 'None':
        """Set field default value."""
        self._field.default = value

    @default.deleter
    def default(self) -> 'None':
        """Delete field default value."""
        self._field.default = NoValue

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._field.template

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._field.length

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return True

    @property
    def field(self) -> 'FieldBase[_TC]':
        """Field instance."""
        return self._field

    def __init__(self, selector: 'Callable[[dict[str, Any]], FieldBase[_TC]]' = lambda _: NoValueField()) -> 'None':  # type: ignore[assignment,return-value]
        #self._name = '<switch>'
        self._field = cast('FieldBase[_TC]', NoValueField())
        self._selector = selector

    def __call__(self, packet: 'dict[str, Any]') -> 'SwitchField[_TC]':
        """Call field.

        Args:
            packet: Packet data.

        Returns:
            New field instance.

        This method will return a new instance of :class:`SwitchField`
        instead of updating the current instance.

        """
        new_self = copy.copy(self)
        new_self._field = new_self._selector(packet)(packet)
        new_self._field.name = self.name
        return new_self

    def pre_process(self, value: '_TC', packet: 'dict[str, Any]') -> 'Any':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        if self._field is None:
            return NoValue  # type: ignore[unreachable]
        return self._field.pre_process(value, packet)

    def pack(self, value: 'Optional[_TC]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        """
        if self._field is None:
            return b''  # type: ignore[unreachable]
        return self._field.pack(value, packet)

    def post_process(self, value: 'Any', packet: 'dict[str, Any]') -> '_TC':  # pylint: disable=unused-argument
        """Process field value after parsing (unpacking).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        if self._field is None:
            return NoValue  # type: ignore[unreachable]
        return self._field.post_process(value, packet)

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_TC':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        """
        if self._field is None:
            return None  # type: ignore[unreachable]
        return self._field.unpack(buffer, packet)


class SchemaField(FieldBase[_TS]):
    """Schema field for protocol schema.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        schema: Field schema.
        default: Default value for field.
        packet: Optional packet data for unpacking and/or packing purposes.
        callback: Callback function to process field value, which should accept
            the current field and the current packet as its arguments.

    """

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._length  # type: ignore[has-type]

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return True

    @property
    def schema(self) -> 'Type[_TS]':
        """Field schema."""
        return self._schema

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]' = lambda _: -1,
                 schema: 'Optional[Type[_TS]]' = None,
                 default: '_TS | NoValueType | bytes' = NoValue,
                 packet: 'Optional[dict[str, Any]]' = None,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        #self._name = '<schema>'
        self._callback = callback

        if packet is None:
            packet = {}
        self._packet = packet

        if schema is None:
            raise FieldError('Schema field must have a schema.')
        self._schema = schema

        if isinstance(default, bytes):
            default = cast('_TS', schema.unpack(default))  # type: ignore[call-arg,misc]
        self._default = default

        self._length_callback = None
        if not isinstance(length, int):
            self._length_callback, length = length, -1
        self._length = length
        self._template = f'{self._length}s' if self._length >= 0 else '1024s'  # use a reasonable default

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Args:
            packet: Packet data.

        Returns:
            New field instance.

        This method will return a new instance of :class:`SchemaField`
        instead of updating the current instance.

        """
        new_self = copy.copy(self)
        new_self._callback(new_self, packet)
        if new_self._length_callback is not None:
            new_self._length = new_self._length_callback(packet)
            new_self._template = f'{new_self._length}s' if self._length >= 0 else '1024s'  # use a reasonable default
        return new_self

    def pack(self, value: 'Optional[_TS | bytes]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        Notes:
            We will use ``packet`` as a ``__packet__`` key in the packet context
            passed to the underlying :class:`~pcapkit.protocols.schema.schema.Schema`
            for packing purposes.

        """
        if value is None:
            if self._default is NoValue:
                raise NoDefaultValue(f'Field {self.name} has no default value.')
            value = cast('_TS', self._default)

        if isinstance(value, bytes):
            return value

        packet.update(self._packet)
        return value.pack({
            '__packet__': packet,
        })

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_TS':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        Notes:
            We will use ``packet`` as a ``__packet__`` key in the packet context
            passed to the underlying :class:`~pcapkit.protocols.schema.schema.Schema`
            for unpacking purposes.

        """
        if isinstance(buffer, bytes):
            file = io.BytesIO(buffer)  # type: IO[bytes]
        else:
            file = buffer

        packet.update(self._packet)
        return cast('_TS', self._schema.unpack(file, self.length, {  # type: ignore[call-arg,misc]
            '__packet__': packet,
        }))


class ForwardMatchField(FieldBase[_TC]):
    """Schema field for non-capturing forward matching.

    Args:
        field: Field to forward match.

    """

    @property
    def name(self) -> 'str':
        """Field name."""
        return self._field.name

    @name.setter
    def name(self, value: 'str') -> 'None':
        """Set field name."""
        self._field.name = value

    @property
    def default(self) -> '_TC | NoValueType':
        """Field default value."""
        return self._field.default

    @default.setter
    def default(self, value: '_TC | NoValueType') -> 'None':
        """Set field default value."""
        self._field.default = value

    @default.deleter
    def default(self) -> 'None':
        """Delete field default value."""
        self._field.default = NoValue

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._field.template

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._field.length

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return True

    @property
    def field(self) -> 'FieldBase[_TC]':
        """Field instance."""
        return self._field

    def __init__(self, field: 'FieldBase[_TC]') -> 'None':
        #self._name = '<forward_match>'
        self._field = field

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Arguments:
            packet: Packet data.

        Returns:
            Updated field instance.

        This method will return a new instance of :class:`ConditionalField`
        instead of updating the current instance.

        """
        new_self = copy.copy(self)
        new_self._field = new_self._field(packet)
        return new_self

    def pack(self, value: 'Optional[_TC]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        """
        return b''

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_TC':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        """
        return self._field.unpack(buffer, packet)
