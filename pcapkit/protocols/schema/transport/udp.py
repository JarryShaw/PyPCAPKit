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
from pcapkit.utilities.exceptions import BaseError

__all__ = ['UDP']

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.protocols.protocol import ProtocolBase


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
            Processed field value -- the registry member declared for the
            port, or an unregistered member of the same registry, carrying
            the port itself, when the registry declares none. See GitHub
            issue #575.

        Notes:
            See :meth:`pcapkit.protocols.schema.transport.tcp.PortEnumField.post_process`,
            whose notes this mirrors verbatim aside from the transport.

        """
        value = super(EnumField, self).post_process(value, packet)
        proto = Enum_TransportProtocol.udp
        if not (isinstance(value, int) and 0 <= value < (1 << (8 * self.length))):
            return self._namespace.get(value, proto=proto)
        owner = self._namespace._dispatch(value, proto)  # pylint: disable=protected-access
        if not owner.__registry__.getlist(value):  # type: ignore[union-attr]
            try:
                declared = owner._missing_(value)  # pylint: disable=protected-access
            except ValueError as error:
                if isinstance(error, BaseError):
                    raise
                declared = None
            if declared is None:
                return self._unregistered_member(
                    owner, f'unknown [{value:d} - {proto.name}]',
                    svc='unknown', port=value, proto=proto)
        return self._namespace.get(value, proto=proto)


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
                     checksum: 'bytes', payload: 'bytes | Schema | ProtocolBase') -> 'None': ...
