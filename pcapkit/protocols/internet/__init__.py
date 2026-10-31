# -*- coding: utf-8 -*-
# pylint: disable=unused-import,fixme
"""Internet Layer Protocols
==============================

.. module:: pcapkit.protocols.internet

:mod:`pcapkit.protocols.internet` is the collection of all protocols
in the internet layer, with detailed implementation and methods.

"""
# TODO: Implement ECN, Shim6.

# Base Class for Internet Layer
from pcapkit.protocols.internet.internet import Internet

# Utility Classes for Protocols
from pcapkit.protocols.internet.ah import AH
from pcapkit.protocols.internet.esp import ESP
from pcapkit.protocols.internet.icmpv4 import ICMPv4
from pcapkit.protocols.internet.icmpv6 import ICMPv6
from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
from pcapkit.protocols.internet.ipv4 import IPv4
from pcapkit.protocols.internet.ipv6 import IPv6
from pcapkit.protocols.internet.ipx import IPX

# IPv6 Extension Headers
from pcapkit.protocols.internet.hip import HIP
from pcapkit.protocols.internet.hopopt import HOPOPT
from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext
from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
from pcapkit.protocols.internet.ipv6_route import IPv6_Route
from pcapkit.protocols.internet.mh import MH

# Ethertype IEEE 802 Numbers
from pcapkit.const.reg.ethertype import EtherType as ETHERTYPE

# Base Classes
from pcapkit.protocols.internet.icmp import ICMP
from pcapkit.protocols.internet.igmp import IGMP
from pcapkit.protocols.internet.ip import IP
from pcapkit.protocols.internet.ipsec import IPsec

__all__ = [
    'ETHERTYPE',                                        # Protocol Numbers
    'AH', 'ESP', 'ICMP', 'ICMPv4', 'ICMPv6',            # Internet Layer
    'IGMP', 'IGMPv1', 'IGMPv2',
    'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Ext',
    'IPv6_Opts', 'IPv6_Route', 'MH',                    # IPv6 Extension Header
]
