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
from pcapkit.protocols.internet.ah.protocol import AH
from pcapkit.protocols.internet.esp.protocol import ESP
from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4
from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
from pcapkit.protocols.internet.igmpv1.protocol import IGMPv1
from pcapkit.protocols.internet.igmpv2.protocol import IGMPv2
from pcapkit.protocols.internet.igmpv3.protocol import IGMPv3
from pcapkit.protocols.internet.ipv4.protocol import IPv4
from pcapkit.protocols.internet.ipv6.protocol import IPv6
from pcapkit.protocols.internet.ipx.protocol import IPX

# IPv6 Extension Headers
from pcapkit.protocols.internet.hip.protocol import HIP
from pcapkit.protocols.internet.hopopt.protocol import HOPOPT
from pcapkit.protocols.internet.ipv6_frag.protocol import IPv6_Frag
from pcapkit.protocols.internet.ipv6_ext.protocol import IPv6_Ext
from pcapkit.protocols.internet.ipv6_opts.protocol import IPv6_Opts
from pcapkit.protocols.internet.ipv6_route.protocol import IPv6_Route
from pcapkit.protocols.internet.mh.protocol import MH

# Ethertype IEEE 802 Numbers
from pcapkit.const.reg.ethertype import EtherType as ETHERTYPE

# Base Classes
from pcapkit.protocols.internet.icmp.protocol import ICMP
from pcapkit.protocols.internet.igmp.protocol import IGMP
from pcapkit.protocols.internet.ip.protocol import IP
from pcapkit.protocols.internet.ipsec.protocol import IPsec

__all__ = [
    'ETHERTYPE',                                        # Protocol Numbers
    'AH', 'ESP', 'ICMP', 'ICMPv4', 'ICMPv6',            # Internet Layer
    'IGMP', 'IGMPv1', 'IGMPv2', 'IGMPv3',
    'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Ext',
    'IPv6_Opts', 'IPv6_Route', 'MH',                    # IPv6 Extension Header
]
