#!/usr/bin/python3
# -*- coding: utf-8 -*-


import textwrap


# Ethernet Protocol
# Analyser for ethernet protocol header


from jspcap.utilities import Info
from jspcap.protocols.link.link import Link


__all__ = ['Ethernet']


class Ethernet(Link):
    """This class implements Ethernet Protocol.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * layer -- str, `Link`
        * length -- int, header length of corresponding protocol
        * protocol -- str, next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance
        * src -- str, source mac address
        * dst -- str, destination mac address

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor
        * _read_mac_addr -- read MAC address

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Ethernet Protocol'

    @property
    def length(self):
        return 14

    @property
    def protocol(self):
        return self._info.type

    # source mac address
    @property
    def src(self):
        return self._info.src

    # destination mac address
    @property
    def dst(self):
        return self._info.dst

    ##########################################################################
    # Methods.
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
        return self._decode_next_layer(ethernet, _type, length)

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

    def _read_mac_addr(self):
        """Read MAC address."""
        _byte = self._read_fileng(6)
        _addr = '-'.join(textwrap.wrap(_byte.hex(), 2))
        return _addr
