#!/usr/bin/python3
# -*- coding: utf-8 -*-


# User Datagram Protocol
# Analyser for UDP header


from .transport import Transport
from ..utilities import Info


class UDP(Transport):

    __all__ = ['name', 'info', 'length', 'src', 'dst', 'layer', 'protochain']

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

    def __init__(self, _file, length=None):
        self._file = _file
        self._info = Info(self.read_udp(length))

    def __len__(self):
        return 8

    def __length_hint__(self):
        return 8

    ##########################################################################
    # Utilities.
    ##########################################################################

    def read_udp(self, length):
        """Read User Datagram Protocol (UDP).

        Structure of UDP header [RFC 768]:


            0      7 8     15 16    23 24    31
           +--------+--------+--------+--------+
           |     Source      |   Destination   |
           |      Port       |      Port       |
           +--------+--------+--------+--------+
           |                 |                 |
           |     Length      |    Checksum     |
           +--------+--------+--------+--------+
           |
           |          data octets ...
           +---------------- ...

            Octets          Bits          Name                      Discription
              0              0          udp.srcport             Source Port
              2              16         udp.dstport             Destination Port
              4              32         udp.len                 Length (header includes)
              6              48         udp.checksum            Checksum

        """
        _srcp = self._read_unpack(2)
        _dstp = self._read_unpack(2)
        _tlen = self._read_unpack(2)
        _csum = self._read_fileng(2)

        udp = dict(
            srcport = _srcp,
            dstport = _dstp,
            len = _tlen,
            checksum = _csum,
        )

        length = udp['len'] - 8
        return self._read_next_layer(udp, None, length)
