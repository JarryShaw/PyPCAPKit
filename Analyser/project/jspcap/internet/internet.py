#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Internet Layer Protocols
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


class Internet(Protocol):

    __layer__ = 'Internet'


# Internet layer protocols
INTERNET = {
    '0800': 'IPv4',
    '0806': 'ARP',
    '8137': 'IPX',
    '86dd': 'IPv6',
}
