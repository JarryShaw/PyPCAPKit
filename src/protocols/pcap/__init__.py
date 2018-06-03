# -*- coding: utf-8 -*-
"""PCAP file headers

`jspcap.protocols.pcap` contains header descriptions for
PCAP files, including global header and frame header.

"""
from jspcap.protocols.pcap.frame import Frame
from jspcap.protocols.pcap.header import Header


__all__ = ['Frame', 'Header']
