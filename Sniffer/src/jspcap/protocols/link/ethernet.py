#!/usr/bin/python3
# -*- coding: utf-8 -*-


import textwrap


# Ethernet Protocol
# Analyser for ethernet protocol header


from .link import Link
from ..utilities import Info


class Ethernet(Link):

    __all__ = ['name', 'info', 'length', 'src', 'dst', 'layer', 'protocol', 'protochain']

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Ethernet Protocol'

    @property
    def info(self):
        return self._info

    @property
    def length(self):
        return 14

    @property
    def src(self):
        return self._info.src

    @property
    def dst(self):
        return self._info.dst

    @property
    def layer(self):
        return self.__layer__

    @property
    def protocol(self):
        return self._info.type

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None):
        self._file = _file
        self._info = Info(self.read_ethernet(length))

    def __len__(self):
        return 14

    def __length_hint__(self):
        return 14

    ##########################################################################
    # Utilities.
    ##########################################################################

    def read_ethernet(self, length):
        """Read Ethernet Protocol.

        Structure of Ethernet Protocol header [RFC 7042]:
            Octets          Bits          Name                Discription
              0              0          eth.dst           Destination MAC Address
              1              8          eth.src           Source MAC Address
              2              16         eth.type          Protocol (Internet Layer)

        """
        _dstm = self._read_mac_addr()
        _srcm = self._read_mac_addr()
        _type = self._read_protos(2)

        ethernet = dict(
            dst = _dstm,
            src = _srcm,
            type = _type,
        )

        if length is not None:
            length -= 14
        return self._read_next_layer(ethernet, _type, length)

    def _read_mac_addr(self):
        _byte = self._read_fileng(6)
        _addr = '-'.join(textwrap.wrap(_byte.hex(), 2))
        return _addr
