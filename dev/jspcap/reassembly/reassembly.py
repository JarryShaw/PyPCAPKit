#!/usr/bin/python3
# -*- coding: utf-8 -*-


import abc


# Reassembly of Packets
# Abstract Base Class for Reassembly


ABCMeta = abc.ABCMeta
abstractmethod = abc.abstractmethod
abstractproperty = abc.abstractproperty


class Reassembly(tuple):

    __metaclass__ = ABCMeta

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol of current packet
    @abstractproperty
    def name(self):
        pass

    # total number of reassembled packets
    def count(self):
        return len(self._data)

    ##########################################################################
    # Methods.
    ##########################################################################

    @abstractmethod
    def reassembly(self, info):
        pass

    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __new__(cls, info, *, extract=False):
        self = super().__new__(cls)
        return self

    def __init__(self, info, *, extraction=False):
        self._data = self.reassembly(info)
        if extraction:
            self.extraction()
