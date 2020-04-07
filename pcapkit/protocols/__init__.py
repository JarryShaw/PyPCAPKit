# -*- coding: utf-8 -*-
# pylint: disable=unused-import,unused-wildcard-import,fixme
"""protocol family

:mod:`pcapkit.protocols` is collection of all protocol families,
with detailed implementation and methods.

"""
# TODO: Implement specified classes for MAC and IP addresses.

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

__all__ = [
    # Protocol Numbers
    'LINKTYPE', 'ETHERTYPE', 'TP_PROTO',

    # PCAP Headers
    'Header', 'Frame',

    # No Payload
    'NoPayload',

    # Raw Packet
    'Raw',

    # Link Layer
    'ARP', 'DRARP', 'Ethernet', 'InARP', 'L2TP',
    'OSPF', 'RARP', 'VLAN',

    # Internet Layer
    'AH', 'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',

    # IPv6 Extension Header
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Opts',
    'IPv6_Route', 'MH',

    # Transport Layer
    'TCP', 'UDP',

    # Application Layer
    'FTP', 'HTTP',
]
