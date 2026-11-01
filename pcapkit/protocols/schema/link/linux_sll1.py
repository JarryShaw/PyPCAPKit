# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for Linux "cooked" capture encapsulation (``LINUX_SLL``, v1)"""

from typing import TYPE_CHECKING

from pcapkit.const.arp.hardware import Hardware as Enum_Hardware
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt16Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['LinuxSLL1']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class LinuxSLL1(Schema):
    """Header schema for Linux "cooked" capture encapsulation (``LINUX_SLL``, v1).

    ``protocol_type`` is kept as its raw 2 octets here; whether it is an
    :class:`~pcapkit.const.reg.ethertype.EtherType` depends on ``arphrd_type``,
    see :class:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1`.

    """

    #: Packet type (direction).
    packet_type: 'int' = UInt16Field()
    #: ARP hardware type of the interface the packet was seen on.
    arphrd_type: 'Enum_Hardware' = EnumField(length=2, namespace=Enum_Hardware)
    #: Link-layer address length actually in use; may exceed 8.
    link_addr_length: 'int' = UInt16Field()
    #: Link-layer address, padded to 8 octets; only the first
    #: ``min(link_addr_length, 8)`` of them are meaningful.
    link_addr: 'bytes' = BytesField(length=8)
    #: Protocol (internet layer).
    protocol_type: 'int' = UInt16Field()
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, packet_type: 'int', arphrd_type: 'int', link_addr_length: 'int',  # pylint: disable=unused-argument,super-init-not-called
                     link_addr: 'bytes', protocol_type: 'int',  # pylint: disable=unused-argument
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements
