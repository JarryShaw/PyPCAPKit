# -*- coding: utf-8 -*-
"""Engine Support
====================

.. module:: pcapkit.foundation.engines

:mod:`pcapkit.foundation.engines` is a collection of engines
support for :mod:`pcapkit`, including but not limited to the
built-in PCAP and `PCAP-NG`_ file support, :mod:`Scapy <scapy>`,
`PyShark`_, `DPKT`_, `PyPCAP`_, `pcap-ct`_ and `PyPCAPFile`_ 3rd party
engine support.

.. _PCAP-NG: https://wiki.wireshark.org/Development/PcapNg

"""
# Base class
from pcapkit.foundation.engines.engine import Engine

# Built-in engines
from pcapkit.foundation.engines.pcap import PCAP
from pcapkit.foundation.engines.pcapng import PCAPNG

# 3rd party engines
from pcapkit.foundation.engines.scapy import Scapy
from pcapkit.foundation.engines.dpkt import DPKT
from pcapkit.foundation.engines.pyshark import PyShark
from pcapkit.foundation.engines.pypcap import PyPCAP
from pcapkit.foundation.engines.pcap_ct import PCAP_CT
from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

__all__ = [
    'PCAP', 'PCAPNG',

    'Scapy', 'DPKT', 'PyShark', 'PyPCAP', 'PCAP_CT', 'PyPCAPFile',
]
