# -*- coding: utf-8 -*-
"""protocol family

`jspcap.protocols` is collection of all protocol families,
with detailed implementation and methods.

"""
# Base Class for Protocols
from jspcap.protocols.protocol import Protocol

# Utility Classes for Protocols
from jspcap.protocols.header import Header
from jspcap.protocols.frame import Frame
from jspcap.protocols.raw import Raw

# Protocols & Macros
from jspcap.protocols.link import *
from jspcap.protocols.internet import *
from jspcap.protocols.transport import *
from jspcap.protocols.application import *

# Deprecated / Base Protocols
from jspcap.protocols.internet.ip import IP
from jspcap.protocols.internet.ipsec import IPsec
from jspcap.protocols.application.http import HTTP


__all__ = [
    'LINKTYPE', 'ETHERTYPE', 'TP_PROTO',                # Protocol Numbers
    'Raw',                                              # Raw Packet
    'ARP', 'Ethernet', 'L2TP', 'OSPF', 'RARP', 'VLAN',  # Link Layer
    'AH', 'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',         # Internet Layer
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Opts', 'IPv6_Route', 'MH',
                                                        # IPv6 Extension Header
    'TCP', 'UDP',                                       # Transport Layer
    'HTTP',                                             # Application Layer
]
