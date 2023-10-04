# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for IPv6 Fragment Header"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt32Field
from pcapkit.corekit.fields.strings import BitField, PaddingField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['IPv6_Frag']

if TYPE_CHECKING:
    from typing_extensions import TypedDict

    from pcapkit.protocols.protocol import ProtocolBase as Protocol

    class Flags(TypedDict):
        """Fragment offset and flags."""

        #: Fragment offset.
        offset: int
        #: More fragments flag.
        mf: int


@schema_final
class IPv6_Frag(Schema):
    """Header schema for IPv6-Frag packet."""

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Fragment offset and flags.
    flags: 'Flags' = BitField(length=2, namespace={
        'offset': (0, 13),
        'mf': (15, 1),
    })
    #: Identification.
    id: 'int' = UInt32Field()
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next:'Enum_TransType', flags: 'Flags', id: 'int', payload: 'bytes | Schema | Protocol') -> 'None': ...
