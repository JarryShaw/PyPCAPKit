# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for OSPF protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.ospf.authentication import Authentication as Enum_Authentication
from pcapkit.const.ospf.packet import Packet as Enum_Packet
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema

__all__ = ['OSPF']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import Protocol


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
        def __init__(self, reserved: 'bytes', key_id: 'int', len: 'int', seq: 'int') -> 'None': ...


class OSPF(Schema):
    """Header schema for OSPF packet."""

    #: Version.
    version: 'int' = UInt8Field()
    #: Type.
    type: 'Enum_Packet' = EnumField(length=1, namespace=Enum_Packet)
    #: Length.
    length: 'int' = UInt16Field()
    #: Router ID.
    router_id: 'bytes' = BytesField(length=4)
    #: Area ID.
    area_id: 'bytes' = BytesField(length=4)
    #: Checksum.
    checksum: 'bytes' = BytesField(length=2)
    #: Authentication type.
    auth_type: 'Enum_Authentication' = EnumField(length=2, namespace=Enum_Authentication)
    #: Authentication data.
    auth_data: 'bytes' = BytesField(length=8)
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, version: 'int', type: 'Enum_Packet', length: 'int', router_id: 'bytes',
                     area_id: 'bytes', checksum: 'bytes', auth_type: 'Enum_Authentication',
                     auth_data: 'bytes | CrytographicAuthentication', payload: 'bytes | Protocol | Schema') -> 'None': ...
