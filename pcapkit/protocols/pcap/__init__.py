# -*- coding: utf-8 -*-
"""PCAP file headers

`pcapkit.protocols.pcap` contains header descriptions for
PCAP files, including global header and frame header.

"""
from pcapkit.protocols.pcap.frame import Frame
from pcapkit.protocols.pcap.header import Header

__all__ = ['Frame', 'Header']
