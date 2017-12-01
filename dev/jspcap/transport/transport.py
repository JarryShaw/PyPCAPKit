#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Transport Layer Protocols
# Table of corresponding protocols


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


from ..protocol import Protocol


class Transport(Protocol):

    __layer__ = 'Transport'


# Transport layer protocols
TP_PROTO = {
    # IP Suite
    1:  'ICMP',     # Internet Control Message Protocol
    2:  'IGMP',     # Internet Group Management Protocol
    4:  'IP',       # IP in IP (encapsulation)
   41:  'IPv6',     # IPv6 Encapsulation
   58:  'ICMPv6',   # ICMP for IPv6

   # Transport Layer
    6:  'TCP',      # Transmission Control Protocol
   17:  'UDP',      # User Datagram Protocol
   89:  'OSPF',     # Open Shortest Path First
  132:  'SCTP',     # Stream Control Transmission Protocol
}
