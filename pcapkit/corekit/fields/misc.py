# -*- coding: utf-8 -*-
"""miscellaneous field class"""

import io
from typing import TYPE_CHECKING, TypeVar, cast

from pcapkit.corekit.fields.field import NoValue, _Field
from pcapkit.utilities.exceptions import NoDefaultValue

__all__ = ['ConditionalField', 'PayloadField']

if TYPE_CHECKING:
    from typing import Any, IO, Callable, Optional, Type

    from pcapkit.corekit.fields.field import Field, NoValueType
    from pcapkit.protocols.protocol import Protocol

_TC = TypeVar('_TC', bound='Field')
_TP = TypeVar('_TP', bound='Protocol')


class ConditionalField(_Field[_TC]):
    """Conditional value for protocol fields.

    Args:
        field: field instance.
        condition: field condition function (this function should return a bool
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
    def field(self) -> 'Field[_TC]':
        """Field instance."""
        return self._field

    def __init__(self, field: 'Field[_TC]',  # pylint: disable=super-init-not-called
                 condition: 'Callable[[dict[str, Any]], bool]') -> 'None':
        self._field = field  # type: Field[_TC]
        self._condition = condition

    def __call__(self, packet: 'dict[str, Any]') -> 'ConditionalField':
        """Update field attributes.

        Arguments:
            packet: packet data.

        """
        if self._condition(packet):
            self._field(packet)
        return self

    def pre_process(self, value: '_TC', packet: 'dict[str, Any]') -> 'Any':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: field value.
            packet: packet data.

        Returns:
            Processed field value.

        """
        return self._field.pre_process(value, packet)

    def pack(self, value: 'Optional[_TC]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: field value.
            packet: packet data.

        Returns:
            Packed field value.

        """
        if not self._condition(packet):
            return b''
        return self._field.pack(value, packet)

    def post_process(self, value: 'Any', packet: 'dict[str, Any]') -> '_TC':  # pylint: disable=unused-argument
        """Process field value after parsing (unpacking).

        Args:
            value: field value.
            packet: packet data.

        Returns:
            Processed field value.

        """
        return self._field.post_process(value, packet)

    def unpack(self, buffer: 'bytes', packet: 'dict[str, Any]') -> '_TC':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: field buffer.
            packet: packet data.

        Returns:
            Unpacked field value.

        """
        if not self._condition(packet):
            return self._field.default  # type: ignore[return-value]
        return self._field.unpack(buffer, packet)

    def test(self, packet: 'dict[str, Any]') -> 'bool':
        """Test field condition.

        Arguments:
            packet: current packet

        Returns:
            bool: test result

        """
        return self._condition(packet)


class PayloadField(_Field[_TP]):
    """Payload value for protocol fields.

    Args:
        default: field default value.
        protocol: payload protocol.

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
        return self._protocol

    @protocol.setter
    def protocol(self, protocol: 'Type[_TP]') -> 'None':
        """Set payload protocol.

        Arguments:
            protocol: payload protocol

        """
        self._protocol = protocol

    def __init__(self, name: 'str' = 'payload', default: '_TP | NoValueType' = NoValue,
                 protocol: 'Optional[Type[_TP]]' = None,
                 length_hint: 'Callable[[dict[str, Any]], Optional[int]]' = lambda x: None) -> 'None':
        self._name = name
        self._length_hint = length_hint

        if protocol is None:
            from pcapkit.protocols.misc.raw import Raw  # pylint: disable=import-outside-top-level
            protocol = cast('Type[_TP]', Raw)
        self._protocol = protocol

        if default is NoValue:
            from pcapkit.protocols.misc.null import NoPayload  # pylint: disable=import-outside-top-level
            default = cast('_TP', NoPayload())
        self._default = default

        self._length = 0
        self._template = '0s'

    def pack(self, value: 'Optional[_TP | bytes]', packet: 'dict[str, Any]') -> 'bytes':
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
            value = cast('_TP', self._default)

        if isinstance(value, bytes):
            return value
        return value.data

    def unpack(self, buffer: 'bytes | IO[bytes]',
               packet: 'dict[str, Any]', *,
               length: 'Optional[int]' = None) -> '_TP':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: field buffer.
            packet: packet data.
            length: field length.

        Returns:
            Unpacked field value.

        """
        if isinstance(buffer, bytes):
            if length is None:
                length = self.test_length(packet, len(buffer))

            file = io.BytesIO(buffer)  # type: IO[bytes]
        else:
            if length is None:
                current = buffer.tell()
                default_length = buffer.seek(0, io.SEEK_END) - current
                buffer.seek(current)

                length = self.test_length(packet, default_length)
            file = buffer

        return self._protocol(file, length)  # type: ignore[abstract]

    def test_length(self, packet: 'dict[str, Any]', default: 'int') -> 'int':
        """Get field length hint.

        Arguments:
            packet: packet data.
            default: default field length.

        Returns:
            Field length hint.

        """
        value = self._length_hint(packet)
        if value is None:
            value = default

        self._length = value
        self._template = f'{value}s'

        return value
