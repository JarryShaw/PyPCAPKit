#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Internet Layer Protocols
# Table of corresponding protocols


from ..transport import TP_PROTO
from ..protocol import Protocol
from ..utilities import ProtoChain


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

    def _read_next_layer(self, dict_, proto=None, length=None, *, version=4):
        next_ = self._import_next_layer(proto, length, version=version)

        # make next layer protocol name
        if proto is None:
            proto = ''
        name_ = proto.lower() or 'raw'
        proto = proto or None

        # write info and protocol chain into dict
        dict_[name_] = next_[0]
        self._protos = ProtoChain(proto, next_[1])
        return dict_

    def _import_next_layer(self, proto, length, version):
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
