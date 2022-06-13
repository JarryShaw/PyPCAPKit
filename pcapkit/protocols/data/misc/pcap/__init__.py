# -*- coding: utf-8 -*-
"""data models for PCAP file headers"""

# Global header
from pcapkit.protocols.data.misc.pcap.header import Header as PCAP_Header
from pcapkit.protocols.data.misc.pcap.header import MagicNumber as PCAP_MagicNumber

# Frame header
from pcapkit.protocols.data.misc.pcap.frame import Frame as PCAP_Frame
from pcapkit.protocols.data.misc.pcap.frame import FrameInfo as PCAP_FrameInfo

__all__ = [
    # Global header
    'PCAP_Header', 'PCAP_MagicNumber',

    # Frame header
    'PCAP_Frame', 'PCAP_FrameInfo',
]
