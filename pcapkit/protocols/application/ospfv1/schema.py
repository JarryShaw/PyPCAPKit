# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for OSPFv1 protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.ospfv1.authentication import Authentication as Enum_Authentication
from pcapkit.const.ospfv1.packet import Packet as Enum_Packet
from pcapkit.corekit.fields.ipaddress import IPv4AddressField
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema import Schema, schema_final

__all__ = ['OSPFv1']

if TYPE_CHECKING:
    from ipaddress import IPv4Address

    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class OSPFv1(Schema):
    """Header schema for OSPFv1 packet: the 24-octet header of :rfc:`1131`
    Section A.2, laid out as OSPFv2's.

    :rfc:`1131` defines AuType 0 and 1 alone (Appendix E), as
    :class:`~pcapkit.const.ospfv1.authentication.Authentication` names them, and
    each leaves the 64-bit Authentication field to the scheme, so the field is kept
    as its octets whatever the AuType.

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
    #: Authentication type.
    auth_type: 'Enum_Authentication' = EnumField(length=2, namespace=Enum_Authentication)
    #: Authentication data.
    auth_data: 'bytes' = BytesField(length=8)
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['length'] - 24)
    #: Octets captured past the Packet Length; compare
    #: :attr:`OSPFv2.trailer <pcapkit.protocols.application.ospfv2.schema.OSPFv2.trailer>`.
    trailer: 'bytes' = PayloadField(default=b'')

    if TYPE_CHECKING:
        def __init__(self, version: 'int', type: 'Enum_Packet', length: 'int',
                     router_id: 'IPv4Address | bytes | str | int',
                     area_id: 'IPv4Address | bytes | str | int',
                     checksum: 'bytes', auth_type: 'Enum_Authentication', auth_data: 'bytes',
                     payload: 'bytes | ProtocolBase | Schema',
                     trailer: 'bytes' = b'') -> 'None': ...
