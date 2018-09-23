# -*- coding: utf-8 -*-
"""internet protocol

`pcapkit.protocols.internet.ipsec` contains `IP` only,
which is a base class for Internet Protocol (IP) protocol
family, eg. IPv4, IPv6, and IPsec.

"""
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.decorators import seekset

__all__ = ['IP']


class IP(Internet):
    """This class implements all protocols in IP family.

    - Internet Protocol version 4 (IPv4) [RFC 791]
    - Internet Protocol version 6 (IPv6) [RFC 2460]
    - Authentication Header (AH) [RFC 4302]
    - Encapsulating Security Payload (ESP) [RFC 4303]

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance
        * src -- str, source IP address
        * dst -- str, destination IP address

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

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    # source IP address
    @property
    def src(self):
        """Source IP address."""
        return self._info.src

    # destination IP address
    @property
    def dst(self):
        """Destination IP address."""
        return self._info.dst

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls):
        return ('IPv4', 'IPv6')
