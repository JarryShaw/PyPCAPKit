# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for IEEE 802.2 Logical Link Control"""

from typing import TYPE_CHECKING

from pcapkit.const.llc.lsap import LSAP as Enum_LSAP
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field
from pcapkit.protocols.schema import Schema, schema_final

__all__ = ['LLC']

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.protocols.protocol import ProtocolBase


def llc_control_is_long(pkt: 'dict[str, Any]') -> 'bool':
    """Whether the control field is two octets long.

    Args:
        pkt: Packet data.

    Returns:
        Whether the first octet opens an I-format or S-format control field,
        two octets long, rather than a U-format one, of one octet.

    """
    return pkt['control'] & 0b11 != 0b11


@schema_final
class LLC(Schema):
    """Header schema for LLC PDUs."""

    #: DSAP address, its I/G bit included.
    dsap: 'Enum_LSAP' = EnumField(length=1, namespace=Enum_LSAP)
    #: SSAP address, its C/R bit included.
    ssap: 'int' = UInt8Field()
    #: First octet of the control field.
    control: 'int' = UInt8Field()
    #: Second octet of the control field, in the I and S formats.
    control_ext: 'Optional[int]' = ConditionalField(
        UInt8Field(),
        llc_control_is_long,
    )
    #: Information field.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, dsap: 'Enum_LSAP | int', ssap: 'int', control: 'int',
                     control_ext: 'Optional[int]', payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
