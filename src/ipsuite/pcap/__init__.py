# -*- coding: utf-8 -*-
"""PCAP file headers

`jspcap.ipsuite.pcap` contains header constructors for
PCAP files, including global header and frame header.

"""
from jspcap.ipsuite.pcap.header import Header as IPSHeader
from jspcap.ipsuite.pcap.frame import Frame as IPSFrame


__all__ = ['IPSHeader', 'IPSFrame']
