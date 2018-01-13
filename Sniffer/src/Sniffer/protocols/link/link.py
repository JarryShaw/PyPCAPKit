#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Link Layer Protocols
# Table of corresponding protocols


from ..internet import ETHERTYPE
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


# Link-Layer Header Type Values
LINKTYPE = {
    0 : 'Null',     # BSD loopback encapsulation
    1 : 'Ethernet', # IEEE 802.3 Ethernet
  101 : 'Raw',      # Raw IP
  228 : 'IPv4',     # Raw IPv4
  229 : 'IPv6',     # Raw IPv6
  248 : 'SCTP',     # SCTP packets
}


class Link(Protocol):

    __layer__ = 'Link'

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
        _byte = self._read_fileng(size).hex()
        _prot = ETHERTYPE.get(_byte)
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
        if proto == 'ARP':
            from .arp import ARP as Protocol
        elif proto == 'RARP':
            from .rarp import RARP as Protocol
        elif proto == 'IPv4':
            from ..internet import IPv4 as Protocol
        elif proto == 'IPv6':
            from ..internet import IPv6 as Protocol
        elif proto == 'IPX':
            from ..internet import IPX as Protocol
        else:
            data = self._file.read(*[length]) or None
            return data, None
        next_ = Protocol(self._file, length)
        return next_.info, next_.protochain
