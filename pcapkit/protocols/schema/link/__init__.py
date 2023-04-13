# -*- coding: utf-8 -*-
"""header schema for data link layer protocols"""

from pcapkit.protocols.schema.link.arp import ARP
from pcapkit.protocols.schema.link.ethernet import Ethernet
from pcapkit.protocols.schema.link.l2tp import L2TP
from pcapkit.protocols.schema.link.ospf import OSPF
from pcapkit.protocols.schema.link.ospf import \
    CrytographicAuthentication as OSPF_CrytographicAuthentication
from pcapkit.protocols.schema.link.vlan import TCI as VLAN_TCI
from pcapkit.protocols.schema.link.vlan import VLAN

__all__ = [
    'ARP',
    'Ethernet',
    'L2TP',
    'OSPF', 'OSPF_CrytographicAuthentication',
    'VLAN', 'VLAN_TCI',
]
