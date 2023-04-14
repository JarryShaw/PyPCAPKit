# -*- coding: utf-8 -*-
"""Engine Support
====================

:mod:`pcapkit.foundation.engine` is a collection of engines
support for :mod:`pcapkit`, including but not limited to the
built-in PCAP and PCAP-NG file support, :mod:`Scapy <scapy`,
:mod:`PyShark <pyshark>`, :mod:`DPKT <dpkt>` 3rd party engine
support.

"""
# Base class
from pcapkit.foundation.engine.engine import Engine

# Built-in engines
from pcapkit.foundation.engine.pcap import PCAP

# 3rd party engines
from pcapkit.foundation.engine.scapy import Scapy
from pcapkit.foundation.engine.dpkt import DPKT
from pcapkit.foundation.engine.pyshark import PyShark

__all__ = [
    'PCAP',

    'Scapy', 'DPKT', 'PyShark',
]
