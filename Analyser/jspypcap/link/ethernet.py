#!/usr/bin/python3
# -*- coding: utf-8 -*-


import textwrap


# Ethernet Protocol
# Analyser for ethernet protocol header


# from link import Link


##############################################################################
# for unknown reason and never-encountered situation, at current time
# we have to change the working directory to import from parent folders

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from internet.internet import INTERNET
from protocol import Info, Protocol

del sys.path[1]

# and afterwards, we recover the whole scene back to its original state
##############################################################################



class Ethernet(Protocol):

    __all__ = ['name', 'info', 'length', 'src', 'dst', 'layer', 'protocol']

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
        return 'Link Layer'

    @property
    def protocol(self):
        return self._info.type

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file):
        self._file = _file
        self._info = Info(self.read_ethernet())

    def __len__(self):
        return 14

    def __length_hint__(self):
        return 14

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
