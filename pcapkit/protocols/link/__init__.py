# -*- coding: utf-8 -*-
"""link layer protocols

`pcapkit.protocols.link` is collection of all protocols in
link layer, with detailed implementation and methods.

"""
# Base Class for Link Layer
from pcapkit.protocols.link.link import Link

# Utility Classes for Protocols
from pcapkit.protocols.link.arp import ARP
from pcapkit.protocols.link.arp import ARP as InARP
from pcapkit.protocols.link.ethernet import Ethernet
from pcapkit.protocols.link.l2tp import L2TP
from pcapkit.protocols.link.ospf import OSPF
from pcapkit.protocols.link.rarp import RARP
from pcapkit.protocols.link.rarp import RARP as DRARP
from pcapkit.protocols.link.vlan import VLAN

# Link-Layer Header Type Values
from pcapkit.protocols.link.link import LINKTYPE

# TODO: Implements DSL, EAPOL, FDDI, ISDN, NDP, PPP.
__all__ = [
    'LINKTYPE',                             # Protocol Numbers
    'ARP', 'DRARP', 'Ethernet', 'InARP', 'L2TP', 'OSPF', 'RARP', 'VLAN',
                                            # Link Layer Protocols
]
