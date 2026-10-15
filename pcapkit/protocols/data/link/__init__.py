# -*- coding: utf-8 -*-
"""data models for link layer protocols"""

# Address Resolution Protocol
from pcapkit.protocols.data.link.arp import ARP
from pcapkit.protocols.data.link.arp import Address as ARP_Address
from pcapkit.protocols.data.link.arp import Type as ARP_Type

# Ethernet Protocol
from pcapkit.protocols.data.link.ethernet import Ethernet

# Layer Two Tunnelling Protocol
from pcapkit.protocols.data.link.l2tp import L2TP
from pcapkit.protocols.data.link.l2tp import Flags as L2TP_Flags

# BSD Loopback Encapsulation
from pcapkit.protocols.data.link.loopback import Loopback

# 802.1Q/802.1ad VLAN Tag Types
from pcapkit.protocols.data.link.vlan import TCI as VLAN_TCI
from pcapkit.protocols.data.link.vlan import VLAN

__all__ = [
    # Address Resolution Protocol
    'ARP', 'ARP_Address', 'ARP_Type',

    # Ethernet Protocol
    'Ethernet',

    # Layer Two Tunnelling Protocol
    'L2TP', 'L2TP_Flags',

    # BSD Loopback Encapsulation
    'Loopback',

    # 802.1Q/802.1ad VLAN Tag Types
    'VLAN', 'VLAN_TCI',
]
