# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for user datagram protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.const.reg.apptype import TransportProtocol as Enum_TransportProtocol
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt16Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['UDP']

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.protocols.protocol import ProtocolBase as Protocol


class PortEnumField(EnumField):
    """Enumerated value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        signed: Whether the field is signed.
        byteorder: Field byte order.
        bit_length: Field bit length.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Important:
        This class is specifically designed for :class:`~pcapkit.const.reg.apptype.AppType`
        as it is actually a :class:`~enum.StrEnum` class.

    """
    if TYPE_CHECKING:
        _namespace: 'Enum_AppType'

    def pre_process(self, value: 'int | Enum_AppType', packet: 'dict[str, Any]') -> 'int | bytes':
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        if isinstance(value, Enum_AppType):
            value = value.port
        return super().pre_process(value, packet)

    def post_process(self, value: 'int | bytes', packet: 'dict[str, Any]') -> 'Enum_AppType':
        """Process field value after parsing (unpacked).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        value = super(EnumField, self).post_process(value, packet)
        return self._namespace.get(value, proto=Enum_TransportProtocol.udp)


@schema_final
class UDP(Schema):
    """Header schema for UDP packet."""

    #: Source port.
    srcport: 'Enum_AppType' = PortEnumField(length=2, namespace=Enum_AppType)
    #: Destination port.
    dstport: 'Enum_AppType' = PortEnumField(length=2, namespace=Enum_AppType)
    #: Length of UDP packet.
    len: 'int' = UInt16Field()
    #: Checksum of UDP packet.
    checksum: 'bytes' = BytesField(length=2)
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, srcport: 'Enum_AppType | int', dstport: 'Enum_AppType | int', len: 'int',
                     checksum: 'bytes', payload: 'bytes | Schema | Protocol') -> 'None': ...
