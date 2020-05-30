# -*- coding: utf-8 -*-
"""dump utilities

`pcapkit.dumpkit` is the collection of dumpers for
`pcapkit` implementation, which is alike those described
in [`dictdumper`](https://github.com/JarryShaw/dictdumper).

"""
import sys

from pcapkit.protocols.pcap.frame import Frame
from pcapkit.protocols.pcap.header import Header

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
            packet=frame.packet,
            nanosecond=self._nsec,
            **frame.get('frame_info', frame),
        ).data
        with open(self._file, 'ab') as file:
            file.write(packet)
