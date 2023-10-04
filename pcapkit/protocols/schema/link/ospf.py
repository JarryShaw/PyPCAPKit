# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for OSPF protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.ospf.authentication import Authentication as Enum_Authentication
from pcapkit.const.ospf.packet import Packet as Enum_Packet
from pcapkit.corekit.fields.ipaddress import IPv4AddressField
from pcapkit.corekit.fields.misc import PayloadField, SchemaField, SwitchField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['OSPF', 'CrytographicAuthentication']

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Any

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.protocol import ProtocolBase as Protocol


def ospf_auth_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`OSPF.auth_data` field.

    Args:
        pkt: Packet data.

    Returns:
        * If :attr:`OSPF.auth_type` is 2, a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.link.ospf.CrytographicAuthentication` instance.
        * Otherwise, a :class:`~pcapkit.corekit.fields.strings.BytesField` instance.

    """
    if pkt['auth_type'] == Enum_Authentication.Cryptographic_authentication:
        return SchemaField(length=8, schema=CrytographicAuthentication)
    return BytesField(length=8)


@schema_final
class CrytographicAuthentication(Schema):
    """Header schema for OSPF cryptographic authentication."""

    #: Reserved bytes.
    reserved: 'bytes' = PaddingField(length=2)
    #: Key ID.
    key_id: 'int' = UInt8Field()
    #: Length.
    len: 'int' = UInt8Field()
    #: Sequence number.
    seq: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, key_id: 'int', len: 'int', seq: 'int') -> 'None': ...


@schema_final
class OSPF(Schema):
    """Header schema for OSPF packet."""

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
    auth_data: 'bytes | CrytographicAuthentication' = SwitchField(
        selector=ospf_auth_data_selector,
    )
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, version: 'int', type: 'Enum_Packet', length: 'int',
                     router_id: 'IPv4Address | bytes | str | int',
                     area_id: 'IPv4Address | bytes | str | int',
                     checksum: 'bytes', auth_type: 'Enum_Authentication',
                     auth_data: 'bytes | CrytographicAuthentication',
                     payload: 'bytes | Protocol | Schema') -> 'None': ...
