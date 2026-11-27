# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for OSPFv3 protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.ospf.packet import Packet as Enum_Packet
from pcapkit.corekit.fields.ipaddress import IPv4AddressField
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BytesField, PaddingField
from pcapkit.protocols.schema import Schema, schema_final

__all__ = ['OSPFv3']

if TYPE_CHECKING:
    from ipaddress import IPv4Address

    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class OSPFv3(Schema):
    """Header schema for OSPFv3 packet: the 16-octet header of
    :rfc:`5340#appendix-A.3.1`, which has an Instance ID and a reserved octet
    in place of OSPFv2's AuType and Authentication fields.

    .. versionadded:: 1.8.1

    """

    #: Version.
    version: 'int' = UInt8Field()
    #: Type.
    type: 'Enum_Packet' = EnumField(length=1, namespace=Enum_Packet)
    #: Length.
    length: 'int' = UInt16Field()
    #: Router ID.
    router_id: 'IPv4Address' = IPv4AddressField()
    #: Area ID.
    area_id: 'IPv4Address' = IPv4AddressField()
    #: Checksum.
    checksum: 'bytes' = BytesField(length=2)
    #: Instance ID.
    instance_id: 'int' = UInt8Field()
    #: Reserved octet.
    reserved: 'bytes' = PaddingField(length=1)
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['length'] - 16)
    #: Octets captured past the Packet Length; compare
    #: :attr:`OSPFv2.trailer <pcapkit.protocols.application.ospfv2.schema.OSPFv2.trailer>`.
    trailer: 'bytes' = PayloadField(default=b'')

    if TYPE_CHECKING:
        def __init__(self, version: 'int', type: 'Enum_Packet', length: 'int',
                     router_id: 'IPv4Address | bytes | str | int',
                     area_id: 'IPv4Address | bytes | str | int',
                     checksum: 'bytes', instance_id: 'int', reserved: 'bytes',
                     payload: 'bytes | ProtocolBase | Schema',
                     trailer: 'bytes' = b'') -> 'None': ...
