# -*- coding: utf-8 -*-
"""data models for Linux "cooked" capture encapsulation (``LINUX_SLL``, v1)"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from pcapkit.const.arp.hardware import Hardware

__all__ = ['LinuxSLL1']


@info_final
class LinuxSLL1(Protocol):
    """Data model for Linux "cooked" capture encapsulation (``LINUX_SLL``, v1).

    ``protocol_type`` is an :class:`~pcapkit.const.reg.ethertype.EtherType`
    for every :attr:`arphrd_type` except a few -- see
    :class:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1`; it is kept as its
    raw wire value here regardless.

    """

    #: Packet type (direction), where ``0`` is to us, ``1`` broadcast, ``2``
    #: multicast, ``3`` sent to another host promiscuously and ``4`` sent by us.
    packet_type: 'int'
    #: ARP hardware type of the interface the packet was seen on.
    arphrd_type: 'Hardware'
    #: Link-layer address length actually in use; may exceed 8.
    link_addr_length: 'int'
    #: Link-layer address, padded to 8 octets as captured; only the first
    #: :attr:`link_addr_length` of them are meaningful.
    link_addr: 'bytes'
    #: Protocol (internet layer), kept as its raw wire value.
    protocol_type: 'int'

    if TYPE_CHECKING:
        def __init__(self, packet_type: 'int', arphrd_type: 'Hardware', link_addr_length: 'int',  # pylint: disable=unused-argument,super-init-not-called
                     link_addr: 'bytes', protocol_type: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements
