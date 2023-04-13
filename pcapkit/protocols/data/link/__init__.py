# -*- coding: utf-8 -*-
"""data models for link layer protocols"""

# Address Resolution Protocol
from pcapkit.protocols.data.link.arp import ARP
from pcapkit.protocols.data.link.arp import Address as ARP_Address
from pcapkit.protocols.data.link.arp import Type as ARP_Type

# Ethernet Protocol
from pcapkit.protocols.data.link.ethernet import Ethernet

# Open Shortest Path First
from pcapkit.protocols.data.link.ospf import OSPF
from pcapkit.protocols.data.link.ospf import \
    CrytographicAuthentication as OSPF_CrytographicAuthentication

# 802.1Q Customer VLAN Tag Type
from pcapkit.protocols.data.link.vlan import TCI as VLAN_TCI
from pcapkit.protocols.data.link.vlan import VLAN

__all__ = [
    # Address Resolution Protocol
    'ARP', 'ARP_Address', 'ARP_Type',

    # Ethernet Protocol
    'Ethernet',

    # Open Shortest Path First
    'OSPF', 'OSPF_CrytographicAuthentication',

    # 802.1Q Customer VLAN Tag Type
    'VLAN', 'VLAN_TCI',
]
