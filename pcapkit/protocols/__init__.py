# -*- coding: utf-8 -*-
# pylint: disable=unused-import,unused-wildcard-import,fixme
"""Protocol Family
=====================

:mod:`pcapkit.protocols` is collection of all protocol families,
with detailed implementation and methods.

"""
from typing import TYPE_CHECKING

# Base Class for Protocols
from pcapkit.protocols.protocol import Protocol

# Utility Classes for Protocols
from pcapkit.protocols.misc import *

# Protocols & Macros
from pcapkit.protocols.link import *
from pcapkit.protocols.internet import *
from pcapkit.protocols.transport import *
from pcapkit.protocols.application import *

if TYPE_CHECKING:
    from typing import Type

__all__ = [
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
    'FTP', 'HTTP', 'HTTPv1', 'HTTPv2',
]

# protocol registry
__proto__ = {}  # type: dict[str, Type[Protocol]]
for name in __all__:
    __proto__[name.upper()] = globals()[name]

__all__.extend((
    # Protocol Numbers
    'LINKTYPE', 'ETHERTYPE', 'TRANSTYPE',
))
