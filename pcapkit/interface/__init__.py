# -*- coding: utf-8 -*-
# pylint: disable=bad-continuation
"""user interface

:mod:`pcapkit.interface` defines several user-oriented
interfaces, variables, and etc. These interfaces are
designed to help and simplify the usage of :mod:`pcapkit`.

"""

from pcapkit.interface.core import (APP, DPKT, INET, JSON, LINK, PCAP, PLIST, RAW, TRANS, TREE,
                                    MPPipeline, MPServer, PCAPKit, PyShark, Scapy, analyse, extract,
                                    reassemble, trace)

__all__ = [
    'extract', 'analyse', 'reassemble', 'trace',            # interface functions
    'TREE', 'JSON', 'PLIST', 'PCAP',                        # format macros
    'LINK', 'INET', 'TRANS', 'APP', 'RAW',                  # layer macros
    'DPKT', 'Scapy', 'PyShark', 'MPServer', 'MPPipeline', 'PCAPKit',
                                                            # engine macros
]
