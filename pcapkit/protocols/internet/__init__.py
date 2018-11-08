# -*- coding: utf-8 -*-
"""internet layer protocols

`pcapkit.protocols.internet` is collection of all protocols
in internet layer, with detailed implementation and
methods.

"""
# Base Class for Internet Layer
from pcapkit.protocols.internet.internet import Internet

# Utility Classes for Protocols
from pcapkit.protocols.internet.ah import AH
from pcapkit.protocols.internet.ipv4 import IPv4
from pcapkit.protocols.internet.ipv6 import IPv6
from pcapkit.protocols.internet.ipx import IPX

# IPv6 Extension Headers
from pcapkit.protocols.internet.hip import HIP
from pcapkit.protocols.internet.hopopt import HOPOPT
from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
from pcapkit.protocols.internet.ipv6_route import IPv6_Route
from pcapkit.protocols.internet.mh import MH

# Ethertype IEEE 802 Numbers
from pcapkit.protocols.internet.internet import ETHERTYPE

# Deprecated / Base Classes
from pcapkit.protocols.internet.ip import IP
from pcapkit.protocols.internet.ipsec import IPsec

# TODO: Implements ECN, ESP, ICMP, ICMPv6, IGMP, Shim6.
__all__ = [
    'ETHERTYPE',                                        # Protocol Numbers
    'AH', 'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',         # Internet Layer
    'HIP', 'HOPOPT', 'IPv6_Frag',
    'IPv6_Opts', 'IPv6_Route', 'MH',                    # IPv6 Extension Header
]
