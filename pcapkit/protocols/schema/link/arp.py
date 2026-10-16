# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for (inverse) address resolution protocol family"""

from typing import TYPE_CHECKING

from pcapkit.const.arp.hardware import Hardware as Enum_Hardware
from pcapkit.const.arp.operation import Operation as Enum_Operation
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['ARP']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class ARP(Schema):
    """Header schema for ARP packet."""

    #: Hardware type.
    htype: 'Enum_Hardware' = EnumField(length=2, namespace=Enum_Hardware)
    #: Protocol type.
    ptype: 'Enum_EtherType' = EnumField(length=2, namespace=Enum_EtherType)
    #: Hardware address length.
    hlen: 'int' = UInt8Field()
    #: Protocol address length.
    plen: 'int' = UInt8Field()
    #: Operation code.
    oper: 'Enum_Operation' = EnumField(length=2, namespace=Enum_Operation)
    #: Sender hardware address.
    sha: 'bytes' = BytesField(length=lambda pkt: pkt['hlen'])
    #: Sender protocol address.
    spa: 'bytes' = BytesField(length=lambda pkt: pkt['plen'])
    #: Target hardware address.
    tha: 'bytes' = BytesField(length=lambda pkt: pkt['hlen'])
    #: Target protocol address.
    tpa: 'bytes' = BytesField(length=lambda pkt: pkt['plen'])
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, htype: 'int', ptype: 'int', hlen: 'int', plen: 'int',
                     oper: 'int', sha: 'bytes', spa: 'bytes', tha: 'bytes',
                     tpa: 'bytes', payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
