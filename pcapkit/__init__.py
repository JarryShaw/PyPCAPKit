# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position,unused-import,unused-wildcard-import
"""Stream PCAP File Extractor
================================

.. module:: pcapkit

:mod:`pcapkit` is an independent open source library, using only
`DictDumper`_ as its formatted output dumper.

Unlike `Scapy`_, `DPKT`_ and `PyShark`_, :mod:`pcapkit` reads
input files as a stream, frame by frame, to keep memory use low.

============================================= =================================================
Subpackage                                    Contents
============================================= =================================================
Interface (:mod:`pcapkit.interface`)          user-facing functions and macros
Foundation (:mod:`pcapkit.foundation`)        extraction, flow tracing, reassembly and registry APIs
Protocols (:mod:`pcapkit.protocols`)          protocol dissectors
Utilities (:mod:`pcapkit.utilities`)          auxiliary functions and tools
CoreKit (:mod:`pcapkit.corekit`)              core data structures
ToolKit (:mod:`pcapkit.toolkit`)              per-engine reassembly and flow-tracing helpers
DumpKit (:mod:`pcapkit.dumpkit`)              output file formatters
Constants (:mod:`pcapkit.const`)              protocol enumeration registries
Vendor Crawlers (:mod:`pcapkit.vendor`)       crawlers that generate :mod:`pcapkit.const`
============================================= =================================================

"""
###############################################################################
# conda ``_extern`` module support

import os
import sys

_extern = os.path.join(os.path.dirname(os.path.realpath(__file__)), '_extern')
if os.path.exists(_extern):
    sys.path.append(_extern)

###############################################################################

import warnings
from typing import TYPE_CHECKING

import tbtrim

from pcapkit.utilities.exceptions import BaseError
from pcapkit.utilities.importlib import lazy_exports
from pcapkit.utilities.logging import DEVMODE
from pcapkit.utilities.warnings import DevModeWarning

# set up sys.excepthook
if DEVMODE:
    warnings.showwarning('development mode enabled', DevModeWarning,
                         filename=__file__, lineno=0,
                         line=f"PCAPKIT_DEVMODE={os.environ.get('PCAPKIT_DEVMODE', '1')}")
else:
    ROOT = os.path.dirname(os.path.realpath(__file__))
    tbtrim.set_trim_rule(lambda filename: ROOT in os.path.realpath(filename),
                         exception=BaseError, strict=False)

from pcapkit.interface import *

if TYPE_CHECKING:
    from pcapkit.protocols import *

__all__ = [
    'extract', 'reassemble', 'trace',                       # Interface Functions

    'TREE', 'JSON', 'PLIST', 'PCAP',                        # Format Macros
    'LINK', 'INET', 'TRANS', 'APP', 'RAW',                  # Layer Macros
    'DPKT', 'Scapy', 'PyShark', 'PCAPKit',                  # Engine Macros
    'PyPCAP', 'PCAP_CT', 'PyPCAPFile',                      # Engine Macros

    'LINKTYPE', 'ETHERTYPE', 'TRANSTYPE', 'APPTYPE',        # Protocol Numbers

    'Header', 'Frame',                                      # PCAP Headers
    'PCAPNG',                                               # PCAPNG Format

    'NoPayload',                                            # No Payload
    'Raw',                                                  # Raw Packet

    'ARP', 'C_Tag', 'Ethernet', 'FRAD', 'GRE', 'IEEE802_11', 'InARP',  # Link Layer
    'L2TP', 'L2TPv2', 'LinuxSLL', 'LinuxSLL1', 'LinuxSLL2', 'Loopback', 'Netlink',
    'Radiotap', 'S_Tag', 'VLAN',

    'AH', 'ESP', 'ICMP', 'ICMPv4', 'ICMPv6',                # Internet Layer
    'IGMP', 'IGMPv1', 'IGMPv2', 'IGMPv3', 'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',

    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Ext', 'IPv6_Opts', 'IPv6_Route', 'MH',
                                                            # IPv6 Extension Header
    'IP_Pseudo',                                            # IP Pseudo-Header

    'DCCP', 'TCP', 'UDP', 'SCTP',                           # Transport Layer

    'FTP', 'FTP_DATA',                                      # Application Layer
    'HTTP', 'HTTPv1', 'HTTPv2', 'NGAP', 'OSPF',
    'RARP', 'DRARP', 'SSL', 'SSLv2', 'SSLv3', 'TLS', 'DTLS',

    'Data',                                                 # Protocol Data
    'Schema',                                               # Protocol Schema
]

#: version number
__version__ = '1.6.0'

# Protocols are imported the first time they are reached (#2730).
__getattr__, __dir__ = lazy_exports(__name__, globals(), packages=('protocols',))
