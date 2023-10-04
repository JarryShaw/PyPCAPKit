# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for 802.1Q Customer VLAN Tag Type protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.vlan.priority_level import PriorityLevel as Enum_PriorityLevel
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BitField
from pcapkit.protocols.schema.schema import Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = ['VLAN', 'TCI']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

if SPHINX_TYPE_CHECKING:
    from typing_extensions import TypedDict

    class TCIType(TypedDict):
        """Type of 802.1Q Customer VLAN Tag Type tag control information."""

        #: Priority code point.
        pcp: int
        #: Drop eligible indicator.
        dei: int
        #: VLAN identifier.
        vid: int


@schema_final
class TCI(Schema):
    """Header schema for 802.1Q Customer VLAN Tag Type tag control information."""

    #: Priority code point.
    pcp: 'Enum_PriorityLevel' = EnumField(length=1, bit_length=3, namespace=Enum_PriorityLevel)
    #: Drop eligible indicator.
    dei: 'int' = UInt8Field(bit_length=1)
    #: VLAN identifier.
    vid: 'int' = UInt16Field(bit_length=12)

    if TYPE_CHECKING:
        def __init__(self, pcp: 'Enum_PriorityLevel', dei: 'int', vid: 'int') -> 'None': ...


@schema_final
class VLAN(Schema):
    """Header schema for 802.1Q Customer VLAN Tag Type packet."""

    #: Tag control information.
    tci: 'TCIType' = BitField(
        length=2,
        namespace={
            'pcp': (0, 3),
            'dei': (3, 1),
            'vid': (4, 12),
        },
    )
    #: EtherType.
    type: 'Enum_EtherType' = EnumField(length=2, namespace=Enum_EtherType)
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, tci: 'TCIType', type: 'Enum_EtherType',
                     payload: 'bytes | Protocol | Schema') -> 'None': ...
