#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Internet Layer Protocols
# Table of corresponding protocols


from ..transport import TP_PROTO
from ..protocol import Protocol


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

    __layer__ = 'Internet'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def protochain(self):
        return self._protos

    ##########################################################################
    # Methods.
    ##########################################################################

    def _read_protos(self, size):
        _byte = self._read_unpack(size)
        _prot = TP_PROTO.get(_byte)
        return _prot

    ##########################################################################
    # Data modules.
    ##########################################################################

    def __new__(cls, _file, length=None):
        self = super().__new__(cls, _file)
        return self

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _import_next_layer(self, proto, length):
        if proto == 'IPv4':
            from .ipv4 import IPv4
            next_ = IPv4(self._file, length, version=4)
            return next_.info, next_.protochain
        elif proto == 'IPv6':
            from .ipv6 import IPv6
            next_ = IPv6(self._file, length, version=6)
            return next_.info, next_.protochain
        elif proto == 'AH':
            from .ah import AH as Protocol
        elif proto == 'TCP':
            from ..transport import TCP as Protocol
        elif proto == 'UDP':
            from ..transport import UDP as Protocol
        else:
            data = self._file.read(*[length]) or None
            return data, None
        next_ = Protocol(self._file, length)
        return next_.info, next_.protochain
