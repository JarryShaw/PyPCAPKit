# -*- coding: utf-8 -*-
"""miscellaneous field class"""

import io
from typing import TYPE_CHECKING, TypeVar, cast

from pcapkit.corekit.fields.field import _Field
from pcapkit.protocols.misc.null import NoPayload
from pcapkit.protocols.misc.raw import Raw
from pcapkit.utilities.exceptions import NoDefaultValue, UnsupportedCall

__all__ = ['ConditionalField', 'PayloadField']

if TYPE_CHECKING:
    from typing import Any, BinaryIO, Callable, Optional, Type, NoReturn

    from pcapkit.corekit.fields.field import Field
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

    @property
    def default(self) -> 'Optional[_TC]':
        """Field default value."""
        return self._field.default

    @default.setter
    def default(self, value: '_TC') -> 'None':
        """Set field default value."""
        self._field.default = value

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._field.template

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._field.length

    @property
    def field(self) -> 'Field[_TC]':
        """Field instance."""
        return self._field

    def __init__(self, field: 'Field[_TC]',  # pylint: disable=super-init-not-called
                 condition: 'Callable[[dict[str, Any]], bool]') -> 'None':
        self._field = field  # type: Field[_TC]
        self._condition = condition

    def __call__(self, packet: 'dict[str, Any]') -> 'None':
        """Update field attributes.

        Arguments:
            packet: packet data.

        """
        if not self._condition(packet):
            return
        self._field(packet)

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
        name: field name.
        default: field default value.
        protocol: payload protocol.

    """

    @property
    def name(self) -> 'str':
        """Field name."""
        return self._name

    @property
    def template(self) -> 'NoReturn':
        """Field template."""
        raise UnsupportedCall(f"{self.__class__.__name__} object has no attribute 'template'.")

    @property
    def length(self) -> 'NoReturn':
        """Field size."""
        raise UnsupportedCall(f"{self.__class__.__name__} object has no attribute 'length'.")

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

    def __init__(self, name: 'str' = 'payload', default: 'Optional[_TP]' = None,
                 protocol: 'Type[_TP]' = Raw) -> 'None':  # type: ignore[assignment]
        self._name = name
        self._protocol = protocol

        if default is None:
            default = cast('_TP', NoPayload())
        self._default = default

    def pack(self, value: 'Optional[_TP | bytes]', packet: 'dict[str, Any]') -> 'bytes':
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

        if isinstance(value, bytes):
            return value
        return value.data

    def unpack(self, buffer: 'bytes | BinaryIO', packet: 'dict[str, Any]') -> '_TP':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: field buffer.
            packet: packet data.

        Returns:
            Unpacked field value.

        """
        if isinstance(buffer, bytes):
            file = io.BytesIO(buffer)  # type: BinaryIO
        else:
            file = buffer
        return self._protocol(file)  # type: ignore[abstract]
