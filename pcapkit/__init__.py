# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position,unused-import,unused-wildcard-import
"""Stream PCAP File Extractor
================================

.. module:: pcapkit

:mod:`pcapkit` is an independent open source library, using only
`DictDumper`_ as its formatted output dumper.

.. _DictDumper: https://dictdumper.jarryshaw.me

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

  User interface for the :mod:`pcapkit` library, which
  standardises and simplifies the usage of this library.

- Foundation (:mod:`pcapkit.foundation`)

  Synthesises file I/O and protocol analysis, coordinates
  information exchange in all network layers, as well as
  provides the foundamental functions for :mod:`pcapkit`.

- Protocols (:mod:`pcapkit.protocols`)

  Collection of all protocol family, with detailed
  implementation and methods.

- Utilities (:mod:`pcapkit.utilities`)

  Auxiliary functions and tools for :mod:`pcapkit`.

- CoreKit (:mod:`pcapkit.corekit`)

  Core utilities for :mod:`pcapkit` implementation, mainly
  for internal data structure and processing.

- ToolKit (:mod:`pcapkit.toolkit`)

  Auxiliary tools for :mod:`pcapkit` to support the multiple
  extraction engines with a unified interface.

- DumpKit (:mod:`pcapkit.dumpkit`)

  File output formatters for :mod:`pcapkit`.

- Constants (:mod:`pcapkit.const`)

  Constant enumerations used in :mod:`pcapkit` for protocol
  family extraction and representation.

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

import tbtrim

from pcapkit.utilities.exceptions import BaseError
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

from pcapkit.foundation.registry import *
from pcapkit.interface import *
from pcapkit.protocols import *
from pcapkit.toolkit import *

__all__ = [
    'extract', 'reassemble', 'trace',                       # Interface Functions

    'TREE', 'JSON', 'PLIST', 'PCAP',                        # Format Macros
    'LINK', 'INET', 'TRANS', 'APP', 'RAW',                  # Layer Macros
    'DPKT', 'Scapy', 'PyShark', 'PCAPKit',                  # Engine Macros

    'LINKTYPE', 'ETHERTYPE', 'TRANSTYPE', 'APPTYPE',        # Protocol Numbers

    'NoPayload',                                            # No Payload
    'Raw',                                                  # Raw Packet

    'ARP', 'Ethernet', 'L2TP', 'OSPF', 'RARP', 'VLAN',      # Link Layer

    'AH', 'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',             # Internet Layer
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Opts', 'IPv6_Route', 'MH',
                                                            # IPv6 Extension Header

    'TCP', 'UDP',                                           # Transport Layer

    'FTP', 'FTP_DATA',                                      # Application Layer
    'HTTP',
]

#: version number
__version__ = '1.3.1.post28'
