# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for internetwork packet exchange protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.ipx.packet import Packet as Enum_Packet
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['IPX']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase as Protocol


@schema_final
class IPX(Schema):
    """Header schema for IPX packet."""

    #: Checksum.
    chksum: 'bytes' = BytesField(length=2)
    #: Packet length (header includes).
    len: 'int' = UInt16Field()
    #: Transport control (hop count).
    count: 'int' = UInt8Field()
    #: Packet type.
    type: 'Enum_Packet' = EnumField(length=1, namespace=Enum_Packet)
    #: Destination address.
    dst: 'bytes' = BytesField(length=12)
    #: Source address.
    src: 'bytes' = BytesField(length=12)
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['len'] - 30)

    if TYPE_CHECKING:
        def __init__(self, chksum: 'bytes', len: 'int', count: 'int', type: 'Enum_Packet',
                     dst: 'bytes', src: 'bytes', payload: 'bytes | Protocol | Schema') -> 'None': ...
