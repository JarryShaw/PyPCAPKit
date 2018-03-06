#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Base Class for Link Layer
from jspcap.protocols.link.link import Link

# Utility Classes for Protocols
from jspcap.protocols.link.arp import ARP
from jspcap.protocols.link.ethernet import Ethernet
from jspcap.protocols.link.l2tp import L2TP
from jspcap.protocols.link.ospf import OSPF
from jspcap.protocols.link.rarp import RARP

# Link-Layer Header Type Values
from jspcap.protocols.link.link import LINKTYPE
