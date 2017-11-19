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
#
#
# class Transport(Protocol):
#
#     __layer__ = 'Transport'


# Transport laywer protocols
TP_PROTO = {
    1:   'ICMP',
    2:   'IGMP',
    6:   'TCP',
    17:  'UDP',
    41:  'ENCAP',
    89:  'OSPF',
    132: 'SCTP',
}
