# -*- coding: utf-8 -*-
"""

"""
from jspcap.ipsuite.pcap.frame import Frame
from jspcap.ipsuite.pcap.header import Header


__all__ = ['PCAP']


class PCAP:
    """PCAP file dumper."""
    def __init__(self, filename, *, protocol):
        self._file = filename
        packet = Header(protocol=protocol).data
        with open(self._file, 'wb') as file:
            file.write(packet)

    def __call__(self, frame, **kwargs):
        packet = Frame(frame).data
        with open(self._file, 'ab') as file:
            file.write(packet)
