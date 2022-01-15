# -*- coding: utf-8 -*-
"""data models for link layer protocols"""

from pcapkit.protocols.data.link.arp import ARP, Address as ARP_Address, Type as ARP_Type
from pcapkit.protocols.data.link.ethernet import Ethernet
from pcapkit.protocols.data.link.ospf import OSPF, CrytographicAuthentication as OSPF_CrytographicAuthentication

__all__ = [
    # Address Resolution Protocol
    'ARP', 'ARP_Address', 'ARP_Type',

    # Ethernet Protocol
    'Ethernet',

    # Open Shortest Path First
    'OSPF', 'OSPF_CrytographicAuthentication',
]
