# -*- coding: utf-8 -*-
"""ethernet protocol

`pcapkit.protocols.link.ethernet` contains `Ethernet`
only, which implements extractor for Ethernet Protocol,
whose structure is described as below.

Octets      Bits        Name                    Description
  0           0     eth.dst                 Destination MAC Address
  1           8     eth.src                 Source MAC Address
  2          16     eth.type                Protocol (Internet Layer)

"""
import textwrap

from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.link.link import Link

__all__ = ['Ethernet']


class Ethernet(Link):
    """This class implements Ethernet Protocol.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Link`
        * length -- int, header length of corresponding protocol
        * protocol -- str, next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance
        * src -- str, source mac address
        * dst -- str, destination mac address

    Methods:
        * decode_bytes -- try to decode bytes into str
        * decode_url -- decode URLs into Unicode
        * read_ethernet -- read Ethernet Protocol

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _read_packet -- read raw packet data
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor
        * _read_mac_addr -- read MAC address

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol."""
        return 'Ethernet Protocol'

    @property
    def length(self):
        """Header length of current protocol."""
        return 14

    @property
    def protocol(self):
        """Name of next layer protocol."""
        return self._info.type

    # source mac address
    @property
    def src(self):
        """Source mac address."""
        return self._info.src

    # destination mac address
    @property
    def dst(self):
        """Destination mac address."""
        return self._info.dst

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_ethernet(self, length):
        """Read Ethernet Protocol.

        Structure of Ethernet Protocol header [RFC 7042]:
            Octets      Bits        Name                    Description
              0           0     eth.dst                 Destination MAC Address
              1           8     eth.src                 Source MAC Address
              2          16     eth.type                Protocol (Internet Layer)

        """
        if length is None:
            length = len(self)

        _dstm = self._read_mac_addr()
        _srcm = self._read_mac_addr()
        _type = self._read_protos(2)

        ethernet = dict(
            dst=_dstm,
            src=_srcm,
            type=_type,
        )

        length -= 14
        ethernet['packet'] = self._read_packet(header=14, payload=length)

        return self._decode_next_layer(ethernet, _type, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, **kwargs):
        self._file = _file
        self._info = Info(self.read_ethernet(length))

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
