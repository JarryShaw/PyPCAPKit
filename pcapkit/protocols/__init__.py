# -*- coding: utf-8 -*-
# pylint: disable=unused-import,unused-wildcard-import,fixme
"""Protocol Family
=====================

.. module:: pcapkit.protocols

:mod:`pcapkit.protocols` is a collection of all protocol families,
with detailed implementation and methods.

Each protocol class, and :data:`__proto__`, is imported the first time it is
reached rather than with this package, through
:func:`~pcapkit.utilities.importlib.lazy_exports` (:issue:`2730`).

"""
from typing import TYPE_CHECKING

# NOTE: ahead of any protocol module: defining ``Protocol`` imports Raw and
# NoPayload, which import it back, so either imported first is met half-built.
# Base Class for Protocols
from pcapkit.protocols.protocol import Protocol

# Protocol Data
from pcapkit.protocols import data
from pcapkit.protocols.data import Data

# Protocol Schema
from pcapkit.protocols import schema
from pcapkit.protocols.schema import Schema

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from typing import Type

    from pcapkit.protocols.protocol import ProtocolBase

    # Utility Classes for Protocols
    from pcapkit.protocols.misc import *

    # Protocols & Macros
    from pcapkit.protocols.link import *
    from pcapkit.protocols.internet import *
    from pcapkit.protocols.transport import *
    from pcapkit.protocols.application import *

    #: dict[str, ~typing.Type[~pcapkit.protocols.protocol.ProtocolBase]]: Protocol registry.
    __proto__ = {}  # type: dict[str, Type[ProtocolBase]]

__all__ = [
    # PCAP Headers
    'Header', 'Frame',

    # PCAPNG Format
    'PCAPNG',

    # No Payload
    'NoPayload',

    # Raw Packet
    'Raw',

    # Link Layer
    'ARP', 'C_Tag', 'Ethernet', 'FRAD', 'GRE', 'IEEE802_11', 'InARP', 'L2TP', 'L2TPv2',
    'LinuxSLL', 'LinuxSLL1', 'LinuxSLL2', 'Loopback', 'Netlink', 'Radiotap', 'S_Tag', 'VLAN',

    # Internet Layer
    'AH', 'ESP', 'ICMP', 'ICMPv4', 'ICMPv6', 'IGMP', 'IGMPv1', 'IGMPv2', 'IGMPv3',
    'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',

    # IP Pseudo-Header
    'IP_Pseudo',

    # IPv6 Extension Header
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Ext', 'IPv6_Opts',
    'IPv6_Route', 'MH',

    # Transport Layer
    'DCCP', 'TCP', 'UDP', 'SCTP',

    # Application Layer
    'FTP', 'FTP_DATA',
    'HTTP', 'HTTPv1', 'HTTPv2',
    'NGAP',
    'OSPF',
    'RARP', 'DRARP',
    'SSL', 'SSLv2', 'SSLv3', 'TLS', 'DTLS',

    # Protocol Numbers
    'LINKTYPE', 'ETHERTYPE', 'TRANSTYPE', 'APPTYPE',

    # Protocol Data
    'Data', 'data',

    # Protocol Schema
    'Schema', 'schema',
]

# NOTE: ``Protocol`` is bound above, and named here so that ``dir()`` lists it.
__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'Protocol': ('protocol', 'Protocol'),
    '__proto__': ('registry', '__proto__'),
}, packages=('misc', 'link', 'internet', 'transport', 'application'))
