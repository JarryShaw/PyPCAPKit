# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for mobility header"""

from typing import TYPE_CHECKING

from pcapkit.const.mh.packet import Packet as Enum_Packet
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field
from pcapkit.corekit.fields.strings import BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema

__all__ = ['MH']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import Protocol


class MH(Schema):
    """Header schema for MH packets."""

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Header length.
    length: 'int' = UInt8Field()
    #: MH type.
    type: 'Enum_Packet' = EnumField(length=1, namespace=Enum_Packet)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Checksum.
    chksum: 'bytes' = BytesField(length=2)
    #: Message data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] * 8 + 2)
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType', length: 'int', type: 'Enum_Packet',
                     chksum: 'bytes', data: 'bytes', payload: 'bytes | Protocol | Schema') -> 'None': ...
