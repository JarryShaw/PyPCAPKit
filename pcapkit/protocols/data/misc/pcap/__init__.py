# -*- coding: utf-8 -*-
"""data models for PCAP file headers"""

from pcapkit.protocols.data.misc.pcap.frame import Frame as PCAP_Frame, FrameInfo as PCAP_FrameInfo
from pcapkit.protocols.data.misc.pcap.header import Header as PCAP_Header, MagicNumber as PCAP_MagicNumber

__all__ = [
    # Global header
    'PCAP_Header', 'PCAP_MagicNumber',

    # Frame header
    'PCAP_Frame', 'PCAP_FrameInfo',
]
