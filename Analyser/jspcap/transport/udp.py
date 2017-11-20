#!/usr/bin/python3
# -*- coding: utf-8 -*-


# User Datagram Protocol
# Analyser for UDP header


from ..protocol import Info, Protocol


class UDP(Protocol):

    __all__ = ['name', 'info', 'length', 'src', 'dst', 'layer']

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'User Datagram Protocol'

    @property
    def info(self):
        return self._info

    @property
    def length(self):
        return 8

    @property
    def src(self):
        return self._info.src

    @property
    def dst(self):
        return self._info.dst

    @property
    def layer(self):
        return self.__layer__

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file):
        self._file = _file
        self._info = Info(self.read_udp())

    def __len__(self):
        return 8

    def __length_hint__(self):
        return 8

    ##########################################################################
    # Utilities.
    ##########################################################################

    def read_udp(self):
        """Read User Datagram Protocol (UDP).

        Structure of UDP header:
            Octets          Bits          Name                      Discription
              0              0          udp.srcport             Source Port
              2              16         udp.dstport             Destination Port
              4              32         udp.len                 Length
              6              48         udp.checksum            Checksum

        """
        _srcp = self.read_unpack(self._file, 2)
        _dstp = self.read_unpack(self._file, 2)
        _tlen = self.read_unpack(self._file, 2)
        _csum = self._file.read(2)

        udp = dict(
            srcport = _srcp,
            dstport = _dstp,
            len = _tlen,
            checksum = _csum,
        )

        return udp
