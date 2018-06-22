# -*- coding: utf-8 -*-
"""dump utilities

`jspcap.dumpkit` is the collection of dumpers for
`jspcap` implementation, which is alike those described
in [`jsformat`](https://github.com/JarryShaw/jsformat).

"""
from jspcap.ipsuite.pcap.frame import Frame
from jspcap.ipsuite.pcap.header import Header


__all__ = ['PCAP']



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

    def __init__(self, filename, *, protocol):
        self._file = filename
        packet = Header(protocol=protocol).data
        with open(self._file, 'wb') as file:
            file.write(packet)

    def __call__(self, frame, **kwargs):
        packet = Frame(frame).data
        with open(self._file, 'ab') as file:
            file.write(packet)
