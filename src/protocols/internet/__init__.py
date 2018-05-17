# -*- coding: utf-8 -*-
"""internet layer protocols

`jspcap.protocols.internet` is collection of all protocols
in internet layer, with detailed implementation and
methods.

"""
# Base Class for Internet Layer
from jspcap.protocols.internet.internet import Internet

# Utility Classes for Protocols
from jspcap.protocols.internet.ah import AH
from jspcap.protocols.internet.ipv4 import IPv4
from jspcap.protocols.internet.ipv6 import IPv6
from jspcap.protocols.internet.ipx import IPX

# IPv6 Extension Headers
from jspcap.protocols.internet.hip import HIP
from jspcap.protocols.internet.hopopt import HOPOPT
from jspcap.protocols.internet.ipv6_frag import IPv6_Frag
from jspcap.protocols.internet.ipv6_opts import IPv6_Opts
from jspcap.protocols.internet.ipv6_route import IPv6_Route
from jspcap.protocols.internet.mh import MH

# Ethertype IEEE 802 Numbers
from jspcap.protocols.internet.internet import ETHERTYPE

# Deprecated / Base Classes
from jspcap.protocols.internet.ip import IP
from jspcap.protocols.internet.ipsec import IPsec


__all__ = [
    'ETHERTYPE',                                        # Protocol Numbers
    'AH', 'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',         # Internet Layer
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Opts', 'IPv6_Route', 'MH',
                                                        # IPv6 Extension Header
]
