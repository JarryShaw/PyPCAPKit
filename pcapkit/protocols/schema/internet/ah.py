# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for authentication header"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['AH']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase as Protocol


@schema_final
class AH(Schema):
    """Header schema for AH packet."""

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Payload length.
    len: 'int' = UInt8Field()
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Security parameters index.
    spi: 'int' = UInt32Field()
    #: Sequence number field.
    seq: 'int' = UInt32Field()
    #: Integrity check value.
    icv: 'bytes' = BytesField(length=lambda pkt: (pkt['len'] + 2) * 4 - 12)
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType', len: 'int', spi: 'int', seq: 'int',
                     icv: 'bytes', payload: 'bytes | Protocol | Schema') -> 'None': ...
