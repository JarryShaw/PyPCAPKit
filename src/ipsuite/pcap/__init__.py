# -*- coding: utf-8 -*-
"""PCAP file headers

`pcapkit.ipsuite.pcap` contains header constructors for
PCAP files, including global header and frame header.

"""
from pcapkit.ipsuite.pcap.header import Header as IPSHeader
from pcapkit.ipsuite.pcap.frame import Frame as IPSFrame

__all__ = ['IPSHeader', 'IPSFrame']
