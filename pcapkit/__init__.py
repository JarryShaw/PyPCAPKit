# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position, unused-import, unused-wildcard-import, bad-continuation
"""stream pcap file extractor

:mod:`pcapkit` is an independent open source library, using only
`DictDumper`_ as its formatted output dumper.

.. _DictDumper: https://dictdumper.jarryshaw.me

    There is a project called |jspcapy|_ works on :mod:`pcapkit`,
    which is a command line tool for PCAP extraction.

Unlike popular PCAP file extractors, such as `Scapy`_,
`DPKT`_, `PyShark`_, and etc, :mod:`pcapkit` uses streaming
strategy to read input files. That is to read frame by
frame, decrease occupation on memory, as well as enhance
efficiency in some way.

.. _Scapy: https://scapy.net
.. _DPKT: https://dpkt.readthedocs.io
.. _PyShark: https://kiminewt.github.io/pyshark

In :mod:`pcapkit`, all files can be described as following eight
different components.

- Interface (:mod:`pcapkit.interface`)

  user interface for the :mod:`pcapkit` library, which
  standardise and simplify the usage of this library

- Foundation (:mod:`pcapkit.foundation`)

  synthesise file I/O and protocol analysis, coordinate
  information exchange in all network layers

- Reassembly (:mod:`pcapkit.reassembly`)

  base on algorithms described in :rfc:`815`,
  implement datagram reassembly of IP and TCP packets

- Protocols (:mod:`pcapkit.protocols`)

  collection of all protocol family, with detailed
  implementation and methods

- Utilities (:mod:`pcapkit.utilities`)

  collection of utility functions and classes

- CoreKit (:mod:`pcapkit.corekit`)

  core utilities for :mod:`pcapkit` implementation

- ToolKit (:mod:`pcapkit.toolkit`)

  utility tools for :mod:`pcapkit` implementation

- DumpKit (:mod:`pcapkit.dumpkit`)

  dump utilities for :mod:`pcapkit` implementation

"""
import os
import warnings

import tbtrim

from pcapkit.utilities.exceptions import DEVMODE, BaseError
from pcapkit.utilities.warnings import DevModeWarning

# set up sys.excepthook
if DEVMODE:
    warnings.showwarning('development mode enabled', DevModeWarning,
                         filename=__file__, lineno=0,
                         line=f"PCAPKIT_DEVMODE={os.environ['PCAPKIT_DEVMODE']}")
else:
    ROOT = os.path.dirname(os.path.realpath(__file__))
    tbtrim.set_trim_rule(lambda filename: ROOT in os.path.realpath(filename),
                         exception=BaseError, strict=False)

# All Reference
import pcapkit.all

# Interface
from pcapkit.interface import *

# ToolKit
from pcapkit.toolkit import *

# Protocols
from pcapkit.protocols.null import NoPayload
from pcapkit.protocols.raw import Raw
from pcapkit.protocols.link.arp import ARP
from pcapkit.protocols.link.ethernet import Ethernet
from pcapkit.protocols.application.ftp import FTP
from pcapkit.protocols.link.l2tp import L2TP
from pcapkit.protocols.link.ospf import OSPF
from pcapkit.protocols.link.rarp import RARP
from pcapkit.protocols.link.vlan import VLAN
from pcapkit.protocols.internet.ah import AH
from pcapkit.protocols.internet.hip import HIP
from pcapkit.protocols.internet.hopopt import HOPOPT
from pcapkit.protocols.internet.ip import IP
from pcapkit.protocols.internet.ipsec import IPsec
from pcapkit.protocols.internet.ipv4 import IPv4
from pcapkit.protocols.internet.ipv6 import IPv6
from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
from pcapkit.protocols.internet.ipv6_route import IPv6_Route
from pcapkit.protocols.internet.ipx import IPX
from pcapkit.protocols.internet.mh import MH
from pcapkit.protocols.transport.tcp import TCP
from pcapkit.protocols.transport.udp import UDP
from pcapkit.protocols.application.http import HTTP

__all__ = [
    'extract', 'analyse', 'reassemble', 'trace',            # Interface Functions
    'TREE', 'JSON', 'PLIST', 'PCAP',                        # Format Macros
    'LINK', 'INET', 'TRANS', 'APP', 'RAW',                  # Layer Macros
    'DPKT', 'Scapy', 'PyShark', 'MPServer', 'MPPipeline', 'PCAPKit',
                                                            # Engine Macros
    'NoPayload',                                            # No Payload
    'Raw',                                                  # Raw Packet
    'ARP', 'Ethernet', 'L2TP', 'OSPF', 'RARP', 'VLAN',      # Link Layer
    'AH', 'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',             # Internet Layer
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Opts', 'IPv6_Route', 'MH',
                                                            # IPv6 Extension Header
    'TCP', 'UDP',                                           # Transport Layer
    'FTP', 'HTTP',                                          # Application Layer
]
