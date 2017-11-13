#!/usr/bin/python3
# -*- coding: utf-8 -*-


import textwrap


# Ethernet Protocol
# Analyser for ethernet protocol header


from link import Link

from ..exceptions import StringError
from ..internet.internet import INTERNET


class Ethernet(Link):

    __all__ = ['name', 'layer', 'source', 'destination', 'protocol']

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Ethernet Protocol'

    @property
    def layer(self):
        return self.__layer__

    @property
    def length(self):
        pass

    @property
    def source(self):
        self._dict['src']

    @property
    def destination(self):
        self._dict['dst']

    @property
    def protocol(self):
        self._dict['type']

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file):
        self._file = _file
        self._dict = self.read_ethernet()

    def __len__(self):
        return 14

    def __length_hint__(self):
        return 14

    def __getitem__(self, key):
        if isinstance(key, str):
            try:
                return self._dict[key]
            except KeyError:
                return None
        else:
            raise StringError

    ##########################################################################
    # Utilities.
    ##########################################################################

    def read_ethernet(self):
        """Read Ethernet Protocol.

        Structure of Ethernet Protocol header:
            Octets          Bits          Name                Discription
              0              0          eth.dst           Destination MAC Address
              1              8          eth.src           Source MAC Address
              2              16         eth.type          Protocol (Internet Layer)

        """
        _dstm = self._read_mac_addr()
        _srcm = self._read_mac_addr()
        _type = self._read_eth_type()

        ethernet = dict(
            dst = _dstm,
            src = _srcm,
            type = _type,
        )

        return ethernet

    def _read_mac_addr(self):
        _byte = self._file.read(6)
        _addr = ':'.join(textwrap.wrap(_byte.hex(), 2))
        return _addr

    def _read_eth_type(self):
        _byte = self._file.read(2).hex()
        _type = INTERNET.get(_byte)
        return _type
