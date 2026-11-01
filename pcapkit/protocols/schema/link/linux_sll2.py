# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for Linux "cooked" capture encapsulation v2 (``LINUX_SLL2``)"""

from typing import TYPE_CHECKING

from pcapkit.const.arp.hardware import Hardware as Enum_Hardware
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['LinuxSLL2']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class LinuxSLL2(Schema):
    """Header schema for Linux "cooked" capture encapsulation v2 (``LINUX_SLL2``).

    The field order and widths differ from v1 -- ``protocol_type`` moves to
    the front, ``interface_index`` is new, and ``packet_type`` /
    ``link_addr_length`` shrink from 2 octets to 1 -- see
    :class:`~pcapkit.protocols.schema.link.linux_sll1.LinuxSLL1` for v1.

    """

    #: Protocol (internet layer).
    protocol_type: 'int' = UInt16Field()
    #: Reserved, must be zero.
    reserved: 'int' = UInt16Field()
    #: Index, in the capturing host's own numbering, of the interface the
    #: packet was seen on.
    interface_index: 'int' = UInt32Field()
    #: ARP hardware type of the interface the packet was seen on.
    arphrd_type: 'Enum_Hardware' = EnumField(length=2, namespace=Enum_Hardware)
    #: Packet type (direction).
    packet_type: 'int' = UInt8Field()
    #: Link-layer address length actually in use; may exceed 8.
    link_addr_length: 'int' = UInt8Field()
    #: Link-layer address, padded to 8 octets; only the first
    #: ``min(link_addr_length, 8)`` of them are meaningful.
    link_addr: 'bytes' = BytesField(length=8)
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, protocol_type: 'int', reserved: 'int', interface_index: 'int',  # pylint: disable=unused-argument,super-init-not-called
                     arphrd_type: 'int', packet_type: 'int', link_addr_length: 'int',  # pylint: disable=unused-argument
                     link_addr: 'bytes', payload: 'bytes | ProtocolBase | Schema') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements
