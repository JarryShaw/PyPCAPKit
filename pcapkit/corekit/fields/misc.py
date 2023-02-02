# -*- coding: utf-8 -*-
"""miscellaneous field class"""

import io
from typing import TYPE_CHECKING, TypeVar

from pcapkit.corekit.fields.field import _Field
from pcapkit.protocols.misc.raw import Raw
from pcapkit.protocols.misc.null import NoPayload
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['ConditionalField', 'PayloadField']

if TYPE_CHECKING:
    from typing import Any, Callable, Type, BinaryIO, NoReturn

    from pcapkit.corekit.fields.field import Field
    from pcapkit.protocols.protocol import Protocol

_P = TypeVar('_P', 'int', 'bytes')
_T = TypeVar('_T')
_TP = TypeVar('_TP', bound='Protocol')


class ConditionalField(_Field[_P, _T]):
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
    def default(self) -> 'Any':
        """Field default value."""
        return self._field.default

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._field.template

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._field.length

    @property
    def field(self) -> 'Field[_P, _T]':
        """Field instance."""
        return self._field

    def __init__(self, field: 'Field[_P, _T]',  # pylint: disable=super-init-not-called
                 condition: 'Callable[[dict[str, Any]], bool]') -> 'None':
        self._field = field  # type: Field[_P, _T]
        self._condition = condition

    def test(self, packet: 'dict[str, Any]') -> 'bool':
        """Test field condition.

        Arguments:
            packet: current packet

        Returns:
            bool: test result

        """
        return self._condition(packet)


class PayloadField(_Field[bytes, _TP]):
    """Payload value for protocol fields.

    Args:
        protocol: payload protocol.

    """

    @property
    def name(self) -> 'str':
        """Field name."""
        return self._name

    @property
    def default(self) -> '_TP':
        """Field default value."""
        return self._default

    @property
    def template(self) -> 'NoReturn':
        """Field template."""
        raise UnsupportedCall(f"{self.__class__.__name__} has no attribute 'template'")

    @property
    def length(self) -> 'NoReturn':
        """Field size."""
        raise UnsupportedCall(f"{self.__class__.__name__} has no attribute 'length'")

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

    def __init__(self, name: 'str' = 'payload', default: '_TP' = NoPayload(),  # type: ignore[assignment]
                 protocol: 'Type[_TP]' = Raw) -> 'None':  # type: ignore[assignment]
        self._name = name
        self._protocol = protocol
        self._default = default

    def pack(self, packet: '_TP | bytes') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Arguments:
            value: field value

        Returns:
            Packed field value.

        """
        if isinstance(packet, bytes):
            return packet
        return packet.data

    def unpack(self, data: 'bytes | BinaryIO', length: 'int') -> '_TP':  # type: ignore[override]
        """Unpack field value from :obj:`bytes`.

        Arguments:
            data: field value

        Returns:
            Unpacked field value.

        """
        if isinstance(data, bytes):
            data = io.BytesIO(data)
        return self._protocol(data, length)  # type: ignore[abstract]
