#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Link Layer Protocols
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
# class Link(Protocol):
#
#     __layer__ = 'Link'


# Link laywer protocols
LINKTYPE = {
    0: 'Null',
    1: 'Ethernet',
}
