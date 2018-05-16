# -*- coding: utf-8 -*-
"""stream pcap file extractor

`jspcap` is an independent open source library, using only
[`jsformat`](https://github.com/JarryShaw/jsformat) as
its formatted output dumper.

    There is a project called
    [`jspcapy](https://github.com/JarryShaw/jspcapy)
    works on `jspcap`, which is a command line tool for
    PCAP extraction.

Unlike popular PCAP file extractors, such as `Scapy`,
`dkpt`, `pyshark`, and etc, `jspcap` uses streaming
strategy to read input files. That is to read frame by
frame, decrease occupation on memory, as well as enhance
efficiency in some way.

In `jspcap`, all files can be described as following six
parts.

 - Interface (`jspcap.interface`)
    user interface for the `jspcap` library, which 
    standardises and simplifies the usage of this
    library

 - Extraction (`jspcap.extractor`)
    synthesise file I/O and protocol analysis, coordinate
    information exchange in all network layers

 - Reassembly (`jspcap.reassembly`)
    base on algorithms described in
   [`RFC 815`](https://tools.ietf.org/html/rfc815>),
   implement datagram reassembly of IP and TCP packets

 - Protocls (`jspcap.protocols`)
    collection of all protocol family, with detailed
    implementation and methods

 - Utilities (`jspcap.utilities`)
    collection of four utility functions and classes

 - Exceptions (`jspcap.exceptions`)
    collection of refined custom exceptions

"""
# Interface
from jspcap.interface import *

# Protocols
from jspcap.protocols.raw import Raw
from jspcap.protocols.link.arp import ARP
from jspcap.protocols.link.ethernet import Ethernet
from jspcap.protocols.link.l2tp import L2TP
from jspcap.protocols.link.ospf import OSPF
from jspcap.protocols.link.rarp import RARP
from jspcap.protocols.link.vlan import VLAN
from jspcap.protocols.internet.ah import AH
from jspcap.protocols.internet.hip import HIP
from jspcap.protocols.internet.hopopt import HOPOPT
from jspcap.protocols.internet.ip import IP
from jspcap.protocols.internet.ipsec import IPsec
from jspcap.protocols.internet.ipv4 import IPv4
from jspcap.protocols.internet.ipv6 import IPv6
from jspcap.protocols.internet.ipv6_frag import IPv6_Frag
from jspcap.protocols.internet.ipv6_opts import IPv6_Opts
from jspcap.protocols.internet.ipv6_route import IPv6_Route
from jspcap.protocols.internet.ipx import IPX
from jspcap.protocols.internet.mh import MH
from jspcap.protocols.transport.tcp import TCP
from jspcap.protocols.transport.udp import UDP
from jspcap.protocols.application.http import HTTP


__all__ = [
    'extract', 'analyse', 'reassemble',                 # Interface
    'TREE', 'JSON', 'PLIST',                            # Variables
    'Raw',                                              # Raw Packet
    'ARP', 'Ethernet', 'L2TP', 'OSPF', 'RARP', 'VLAN',  # Link Layer
    'AH', 'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',         # Internet Layer
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Opts', 'IPv6_Route', 'MH',
                                                        # IPv6 Extension Header
    'TCP', 'UDP',                                       # Transport Layer
    'HTTP',                                             # Application Layer
]
