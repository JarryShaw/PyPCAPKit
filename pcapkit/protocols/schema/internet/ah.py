# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for authentication header"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['AH']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase

#: Length of the fixed part of an IP Authentication Header (AH), before its
#: Integrity Check Value, :rfc:`4302#section-2`. The one home of this value
#: (:issue:`1739`), here so that the schema's ICV length and the protocol
#: modules read the same one; it is fixed by the RFC, so it is never
#: configurable.
#:
#: .. versionadded:: 1.5.0
AH_HEADER_LEN = 12


@schema_final
class AH(Schema):
    """Header schema for AH packet.

    .. versionchanged:: 1.5.0

       ``reserved`` is read as an :obj:`int` rather than as zero padding
       :obj:`bytes`, and written back as given (:issue:`1327`).

    """

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Payload length.
    len: 'int' = UInt8Field()
    #: Reserved.
    reserved: 'int' = UInt16Field()
    #: Security parameters index.
    spi: 'int' = UInt32Field()
    #: Sequence number field.
    seq: 'int' = UInt32Field()
    #: Integrity check value.
    icv: 'bytes' = BytesField(length=lambda pkt: (pkt['len'] + 2) * 4 - AH_HEADER_LEN)
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType', len: 'int', reserved: 'int', spi: 'int',
                     seq: 'int', icv: 'bytes',
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
