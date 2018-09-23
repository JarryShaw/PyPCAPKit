# -*- coding: utf-8 -*-
"""dump utilities

`pcapkit.dumpkit` is the collection of dumpers for
`pcapkit` implementation, which is alike those described
in [`dictdumper`](https://github.com/JarryShaw/dictdumper).

"""
import sys

from pcapkit.ipsuite.pcap.frame import Frame
from pcapkit.ipsuite.pcap.header import Header

__all__ = ['PCAP', 'NotImplementedIO']


class NotImplementedIO:
    """Unspecified output format."""
    @property
    def kind(self):
        return NotImplemented

    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        pass


class PCAP:
    """PCAP file dumper."""
    @property
    def kind(self):
        return 'pcap'

    def __init__(self, filename, *, protocol,
                 byteorder=sys.byteorder, nanosecond=False):
        self._file = filename
        self._nsec = nanosecond
        packet = Header(
            network=protocol,
            byteorder=byteorder,
            nanosecond=nanosecond,
        ).data
        with open(self._file, 'wb') as file:
            file.write(packet)

    def __call__(self, frame, **kwargs):
        packet = Frame(
            frame.get('frame_info', frame),
            packet=frame.packet,
            nanosecond=self._nsec
        ).data
        with open(self._file, 'ab') as file:
            file.write(packet)
