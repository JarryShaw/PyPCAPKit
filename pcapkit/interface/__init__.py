# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""User Interface
====================

:mod:`pcapkit.interface` defines several user-oriented
interfaces, variables, and etc. These interfaces are
designed to help and simplify the usage of :mod:`pcapkit`.

"""

from pcapkit.interface.core import (APP, DPKT, INET, JSON, LINK, PCAP, PLIST, RAW, TRANS, TREE,
                                    PCAPKit, PyShark, Scapy, extract,
                                    reassemble, trace)
from pcapkit.interface.misc import follow_tcp_stream

__all__ = [
    'extract', 'reassemble', 'trace',                       # interface functions
    'TREE', 'JSON', 'PLIST', 'PCAP',                        # format macros
    'LINK', 'INET', 'TRANS', 'APP', 'RAW',                  # layer macros
    'DPKT', 'Scapy', 'PyShark', 'PCAPKit',                  # engine macros
]
