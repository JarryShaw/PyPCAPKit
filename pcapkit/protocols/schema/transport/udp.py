# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for user datagram protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.const.reg.apptype import TransportProtocol as Enum_TransportProtocol
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import PortEnumField, UInt16Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['UDP']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class UDP(Schema):
    """Header schema for UDP packet."""

    #: Source port.
    srcport: 'Enum_AppType' = PortEnumField(length=2, namespace=Enum_AppType,
                                            proto=Enum_TransportProtocol.udp)
    #: Destination port.
    dstport: 'Enum_AppType' = PortEnumField(length=2, namespace=Enum_AppType,
                                            proto=Enum_TransportProtocol.udp)
    #: Length of UDP packet.
    len: 'int' = UInt16Field()
    #: Checksum of UDP packet.
    checksum: 'bytes' = BytesField(length=2)
    #: Payload. A Length below the header's own 8 octets leaves the length
    #: negative, which takes the rest of the datagram, as before.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['len'] - 8)
    #: Octets captured past the Length field, c.f.
    #: :attr:`IPv4.trailer <pcapkit.protocols.schema.internet.ipv4.IPv4.trailer>`.
    trailer: 'bytes' = PayloadField(default=b'')

    if TYPE_CHECKING:
        def __init__(self, srcport: 'Enum_AppType | int', dstport: 'Enum_AppType | int', len: 'int',
                     checksum: 'bytes', payload: 'bytes | Schema | ProtocolBase',
                     trailer: 'bytes' = b'') -> 'None': ...
