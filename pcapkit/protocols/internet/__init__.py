# -*- coding: utf-8 -*-
# pylint: disable=unused-import,fixme
"""Internet Layer Protocols
==============================

.. module:: pcapkit.protocols.internet

:mod:`pcapkit.protocols.internet` is the collection of all protocols
in the internet layer, with detailed implementation and methods.

Each protocol class, and the base class
:class:`~pcapkit.protocols.internet.internet.Internet`, is imported the first time
it is reached rather than with this package, through
:func:`~pcapkit.utilities.importlib.lazy_exports` (:issue:`2730`).

"""
# TODO: Implement ECN, Shim6.

from typing import TYPE_CHECKING

# Ethertype IEEE 802 Numbers
from pcapkit.const.reg.ethertype import EtherType as ETHERTYPE
from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    # Base Class for Internet Layer
    from pcapkit.protocols.internet.internet import Internet

    # Utility Classes for Protocols
    from pcapkit.protocols.internet.ah import AH
    from pcapkit.protocols.internet.esp import ESP
    from pcapkit.protocols.internet.icmpv4 import ICMPv4
    from pcapkit.protocols.internet.icmpv6 import ICMPv6
    from pcapkit.protocols.internet.igmpv1 import IGMPv1
    from pcapkit.protocols.internet.igmpv2 import IGMPv2
    from pcapkit.protocols.internet.igmpv3 import IGMPv3
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

    # Base Classes
    from pcapkit.protocols.internet.icmp import ICMP
    from pcapkit.protocols.internet.igmp import IGMP
    from pcapkit.protocols.internet.ip import IP
    from pcapkit.protocols.internet.ipsec import IPsec

__all__ = [
    'ETHERTYPE',                                        # Protocol Numbers
    'AH', 'ESP', 'ICMP', 'ICMPv4', 'ICMPv6',            # Internet Layer
    'IGMP', 'IGMPv1', 'IGMPv2', 'IGMPv3',
    'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Ext',
    'IPv6_Opts', 'IPv6_Route', 'MH',                    # IPv6 Extension Header
]

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'Internet': ('internet', 'Internet'),
    'AH': ('ah', 'AH'),
    'ESP': ('esp', 'ESP'),
    'ICMP': ('icmp', 'ICMP'),
    'ICMPv4': ('icmpv4', 'ICMPv4'),
    'ICMPv6': ('icmpv6', 'ICMPv6'),
    'IGMP': ('igmp', 'IGMP'),
    'IGMPv1': ('igmpv1', 'IGMPv1'),
    'IGMPv2': ('igmpv2', 'IGMPv2'),
    'IGMPv3': ('igmpv3', 'IGMPv3'),
    'IP': ('ip', 'IP'),
    'IPsec': ('ipsec', 'IPsec'),
    'IPv4': ('ipv4', 'IPv4'),
    'IPv6': ('ipv6', 'IPv6'),
    'IPX': ('ipx', 'IPX'),
    'HIP': ('hip', 'HIP'),
    'HOPOPT': ('hopopt', 'HOPOPT'),
    'IPv6_Frag': ('ipv6_frag', 'IPv6_Frag'),
    'IPv6_Ext': ('ipv6_ext', 'IPv6_Ext'),
    'IPv6_Opts': ('ipv6_opts', 'IPv6_Opts'),
    'IPv6_Route': ('ipv6_route', 'IPv6_Route'),
    'MH': ('mh', 'MH'),
})
