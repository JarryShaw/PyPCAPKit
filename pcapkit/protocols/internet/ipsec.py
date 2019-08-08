# -*- coding: utf-8 -*-
"""internet protocol security

`pcapkit.protocols.internet.ipsec` contains `IPsec`
only, which is a base class for Internet Protocol Security
(IPsec) protocol family, eg. AH and ESP (NotImplemented).

"""
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.internet.ip import IP
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = 'IPsec'


class IPsec(IP):
    """Abstract base class for IPsec protocol family.

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

    @property
    def src(self):
        """NotImplemented"""
        raise UnsupportedCall("'{}' object has no attribute 'src'".format(self.__class__.__name__))

    @property
    def dst(self):
        """NotImplemented"""
        raise UnsupportedCall("'{}' object has no attribute 'dst'".format(self.__class__.__name__))

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls):
        return ('AH', 'ESP')
