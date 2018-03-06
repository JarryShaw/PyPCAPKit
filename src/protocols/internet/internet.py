#!/usr/bin/python3
# -*- coding: utf-8 -*-


# TODO: Implements ECN, ESP, HIP, HOPOPT, ICMP, ICMPv6, IGMP, IPv6_Frag, IPv6_NoNxt, IPv6_Opts, IPv6_Route, Mobility, Shim6.


# Internet Layer Protocols
# Table of corresponding protocols


from jspcap.utilities import ProtoChain
from jspcap.protocols.protocol import Protocol
from jspcap.protocols.transport.transport import TP_PROTO


__all__ = ['Internet', 'ETHERTYPE']


# ##############################################################################
# # for unknown reason and never-encountered situation, at current time
# # we have to change the working directory to import from parent folders
#
# import os
# import sys
# sys.path.insert(1, os.path.join(sys.path[0], '..'))
#
# from protocol import Protocol
#
# del sys.path[1]
#
# # and afterwards, we recover the whole scene back to its original state
# ##############################################################################


# Ethertype IEEE 802 Numbers
ETHERTYPE = {
    # Link Layer
    '0806' : 'ARP',     # Address Resolution Protocol
    '8035' : 'RARP',    # Reverse Address Resolution Protocol

    # Internet Layer
    '0800' : 'IPv4',    # Internet Protocol version 4
    '8137' : 'IPX',     # Internetwork Packet Exchange
    '86dd' : 'IPv6',    # Internet Protocol version 6
}


class Internet(Protocol):
    """Abstract base class for internet layer protocol family.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
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
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor

    """
    __layer__ = 'Internet'

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol layer
    @property
    def layer(self):
        return self.__layer__

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size):
        """Read next layer protocol type.

        Keyword arguments:
            size  -- int, buffer size

        """
        _byte = self._read_unpack(size)
        _prot = TP_PROTO.get(_byte)
        return _prot

    def _decode_next_layer(self, dict_, proto=None, length=None, *, version=4):
        """Decode next layer extractor.

        Keyword arguments:
            dict_ -- dict, info buffer
            proto -- str, next layer protocol name
            length -- int, valid (not padding) length
            version -- int, IP version
                        <4 / 6>

        """
        next_ = self._import_next_layer(proto, length, version=version)

        # make next layer protocol name
        name_ = str(proto  or 'Raw').lower()

        # write info and protocol chain into dict
        dict_[name_] = next_[0]
        self._protos = ProtoChain(proto, next_[1])
        return dict_

    def _import_next_layer(self, proto, length=None, version=4):
        """Import next layer extractor.

        Keyword arguments:
            proto -- str, next layer protocol name
            length -- int, valid (not padding) length
            version -- int, IP version (4/6)

        Protocols:
            * IPv4 -- internet layer
            * IPv6 -- internet layer
            * AH -- internet layer
            * TCP -- transport layer
            * UDP -- transport layer

        """
        if proto == 'IPv4':
            from .ipv4 import IPv4 as Protocol
        elif proto == 'IPv6':
            from .ipv6 import IPv6 as Protocol
        elif proto == 'AH':
            from .ah import AH
            next_ = AH(self._file, length, version=version)
        elif proto == 'TCP':
            from ..transport import TCP as Protocol
        elif proto == 'UDP':
            from ..transport import UDP as Protocol
        else:
            data = self._file.read(*[length]) or None
            return data, None
        next_ = Protocol(self._file, length)
        return next_.info, next_.protochain
