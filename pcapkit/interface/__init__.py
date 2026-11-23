# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""User Interface
====================

.. module:: pcapkit.interface

:mod:`pcapkit.interface` defines the user-facing functions and
macros of :mod:`pcapkit`, and exports the options
:func:`~pcapkit.interface.core.extract` takes.

"""

from pcapkit.foundation.options import DumpOptions, ReassemblyOptions, StreamOptions, TraceFlowOptions
from pcapkit.interface.core import (APP, DPKT, INET, JSON, LINK, PCAP, PCAP_CT, PLIST, RAW, TRANS,
                                    TREE, PCAPKit, PyPCAP, PyPCAPFile, PyShark, Scapy, extract,
                                    reassemble, trace)

__all__ = [
    'extract', 'reassemble', 'trace',                       # interface functions
    'DumpOptions', 'ReassemblyOptions',                     # extraction options
    'TraceFlowOptions', 'StreamOptions',                    # extraction options
    'TREE', 'JSON', 'PLIST', 'PCAP',                        # format macros
    'LINK', 'INET', 'TRANS', 'APP', 'RAW',                  # layer macros
    'DPKT', 'Scapy', 'PyShark', 'PCAPKit',                  # engine macros
    'PyPCAP', 'PCAP_CT', 'PyPCAPFile',                      # engine macros
]
