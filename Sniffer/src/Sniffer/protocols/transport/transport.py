#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Transport Layer Protocols
# Table of corresponding protocols


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


# Transport Layer Protocol Numbers
TP_PROTO = {
    # Internet Layer
    1:  'ICMP',     # Internet Control Message Protocol
    2:  'IGMP',     # Internet Group Management Protocol
    4:  'IP',       # IP in IP (encapsulation)
   41:  'IPv6',     # IPv6 Encapsulation
   58:  'ICMPv6',   # ICMP for IPv6

    # IPv6 Extension Header Types
    0:  'HOPOPT',       # IPv6 Hop-by-Hop Option
   43:  'IPv6-Route',   # Routing Header for IPv6
   44:  'IPv6-Frag',    # Fragment Header for IPv6
   50:  'ESP',          # Encapsulating Security Payload
   51:  'AH',           # Authentication Header
   59:  'IPv6-NoNxt',   # No Next Header for IPv6
   60:  'IPv6-Opts',    # Destination Options for IPv6 (before routing / upper-layer header)
  135:  'Mobility',     # Mobility Extension Header for IPv6 (currently without upper-layer header)
  139:  'HIP',          # Host Identity Protocol
  140:  'Shim6',        # Site Multihoming by IPv6 Intermediation

   # Transport Layer
    6:  'TCP',      # Transmission Control Protocol
   17:  'UDP',      # User Datagram Protocol
   89:  'OSPF',     # Open Shortest Path First
  132:  'SCTP',     # Stream Control Transmission Protocol
}


class Transport(Protocol):

    __layer__ = 'Transport'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def protochain(self):
        return self._protos

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
        data = self._file.read(*[length]) or None
        return data, None
