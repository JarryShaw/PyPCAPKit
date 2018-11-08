# -*- coding: utf-8 -*-
"""protocol family

`pcapkit.protocols` is collection of all protocol families,
with detailed implementation and methods.

"""
# Base Class for Protocols
from pcapkit.protocols.protocol import Protocol

# Utility Classes for Protocols
from pcapkit.protocols.raw import *
from pcapkit.protocols.null import *
from pcapkit.protocols.pcap import *

# Protocols & Macros
from pcapkit.protocols.link import *
from pcapkit.protocols.internet import *
from pcapkit.protocols.transport import *
from pcapkit.protocols.application import *

# Deprecated / Base Protocols
from pcapkit.protocols.internet.ip import IP
from pcapkit.protocols.internet.ipsec import IPsec
from pcapkit.protocols.application.http import HTTP

# TODO: Implement specified classes for MAC and IP addresses.
__all__ = [
    'LINKTYPE', 'ETHERTYPE', 'TP_PROTO',                # Protocol Numbers
    'Header', 'Frame',                                  # PCAP Headers
    'NoPayload',                                        # No Payload
    'Raw',                                              # Raw Packet
    'ARP', 'DRARP', 'Ethernet', 'InARP', 'L2TP', 'OSPF', 'RARP', 'VLAN',
                                                        # Link Layer
    'AH', 'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',         # Internet Layer
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Opts', 'IPv6_Route', 'MH',
                                                        # IPv6 Extension Header
    'TCP', 'UDP',                                       # Transport Layer
    'HTTP',                                             # Application Layer
]
