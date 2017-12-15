#!/usr/bin/python3
# -*- coding: utf-8 -*-


import abc


# Reassembler for Packets
# Abstract Base Class for Packet Reassembly


ABCMeta = abc.ABCMeta
abstractmethod = abc.abstractmethod
abstractproperty = abc.abstractproperty


class Reassembler(object):

    __metaclass__ = ABCMeta

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol of current packet
    @abstractproperty
    def name(self):
        pass

    ##########################################################################
    # Methods.
    ##########################################################################



    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __new__(cls, _file):
        self = super().__new__(cls)
        return self
