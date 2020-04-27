# -*- coding: utf-8 -*-
# pylint: disable=unused-import,unused-wildcard-import,fixme
"""link layer protocols

:mod:`pcapkit.protocols.link` is collection of all protocols in
link layer, with detailed implementation and methods.

"""
# TODO: Implements DSL, EAPOL, FDDI, ISDN, NDP, PPP.

# Base Class for Link Layer
from pcapkit.protocols.link.link import Link

# Utility Classes for Protocols
from pcapkit.protocols.link.arp import ARP
from pcapkit.protocols.link.ethernet import Ethernet
from pcapkit.protocols.link.l2tp import L2TP
from pcapkit.protocols.link.ospf import OSPF
from pcapkit.protocols.link.rarp import RARP
from pcapkit.protocols.link.vlan import VLAN

# Link-Layer Header Type Values
from pcapkit.protocols.link.link import LINKTYPE

InARP = ARP
DRARP = RARP

__all__ = [
    # Protocol Numbers
    'LINKTYPE',

    # Link Layer Protocols
    'ARP', 'DRARP', 'Ethernet', 'InARP', 'L2TP',
    'OSPF', 'RARP', 'VLAN',
]
