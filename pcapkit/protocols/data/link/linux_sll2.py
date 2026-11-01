# -*- coding: utf-8 -*-
"""data models for Linux "cooked" capture encapsulation v2 (``LINUX_SLL2``)"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from pcapkit.const.arp.hardware import Hardware

__all__ = ['LinuxSLL2']


@info_final
class LinuxSLL2(Protocol):
    """Data model for Linux "cooked" capture encapsulation v2 (``LINUX_SLL2``).

    ``protocol_type`` is an :class:`~pcapkit.const.reg.ethertype.EtherType`
    for every :attr:`arphrd_type` except a few -- see
    :class:`~pcapkit.protocols.link.linux_sll2.LinuxSLL2`; it is kept as its
    raw wire value here regardless.

    """

    #: Protocol (internet layer), kept as its raw wire value.
    protocol_type: 'int'
    #: Reserved, must be zero.
    reserved: 'int'
    #: Index, in the capturing host's own numbering, of the interface the
    #: packet was seen on.
    interface_index: 'int'
    #: ARP hardware type of the interface the packet was seen on.
    arphrd_type: 'Hardware'
    #: Packet type (direction), where ``0`` is to us, ``1`` broadcast, ``2``
    #: multicast, ``3`` sent to another host promiscuously and ``4`` sent by us.
    packet_type: 'int'
    #: Link-layer address length actually in use; may exceed 8.
    link_addr_length: 'int'
    #: Link-layer address, padded to 8 octets as captured; only the first
    #: :attr:`link_addr_length` of them are meaningful.
    link_addr: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, protocol_type: 'int', reserved: 'int', interface_index: 'int',  # pylint: disable=unused-argument,super-init-not-called
                     arphrd_type: 'Hardware', packet_type: 'int', link_addr_length: 'int',  # pylint: disable=unused-argument
                     link_addr: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements
