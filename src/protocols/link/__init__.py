# -*- coding: utf-8 -*-
"""link layer protocols

`jspcap.protocols.link` is collection of all protocols in
link layer, with detailed implementation and methods.

"""
# TODO: Implements DSL, EAPOL, FDDI, ISDN, NDP, PPP.

# Base Class for Link Layer
from jspcap.protocols.link.link import Link

# Utility Classes for Protocols
from jspcap.protocols.link.arp import ARP
from jspcap.protocols.link.arp import ARP as InARP
from jspcap.protocols.link.ethernet import Ethernet
from jspcap.protocols.link.l2tp import L2TP
from jspcap.protocols.link.ospf import OSPF
from jspcap.protocols.link.rarp import RARP
from jspcap.protocols.link.rarp import RARP as DRARP
from jspcap.protocols.link.vlan import VLAN

# Link-Layer Header Type Values
from jspcap.protocols.link.link import LINKTYPE


__all__ = [
    'LINKTYPE',                             # Protocol Numbers
    'ARP', 'DRARP', 'Ethernet', 'InARP', 'L2TP', 'OSPF', 'RARP', 'VLAN',
                                            # Link Layer Protocols
]
