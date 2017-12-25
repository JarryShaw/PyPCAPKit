#!/usr/bin/python3
# -*- coding: utf-8 -*-


import abc
import copy


# Reassembly of Packets
# Abstract Base Class for Reassembly


from .utilities import Info


ABCMeta = abc.ABCMeta
abstractmethod = abc.abstractmethod
abstractproperty = abc.abstractproperty


class Reassembly(object):
    """Base class for reassembly procedure.

    Keyword arguments:
     - strict : bool, if strict set to True, all datagram will return
                else only implemented ones will submit (False in default)
                < True / False >

    Properties:
     - name : str, protocol of current packet
     - count : int, total number of reassembled packets
     - datagram : tuple, reassembled datagram, which structure may vary
                    according to its protocol

    Methods:
     - reassembly : perform the reassembly procedure
     - submit : submit reassembled payload
     - fetch : fetch datagram
     - index : return datagram index
     - run : run automatically

    """
    __metaclass__ = ABCMeta

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol of current packet
    @abstractproperty
    def name(self):
        pass

    # total number of reassembled packets
    @property
    def count(self):
        return len(self._dtgram)

    # reassembled datagram
    @property
    def datagram(self):
        return self.fetch()

    ##########################################################################
    # Methods.
    ##########################################################################

    # reassembly procedure
    @abstractmethod
    def reassembly(self, info):
        pass

    # submit reassembled payload
    @abstractmethod
    def submit(self, buf):
        pass

    # fetch datagram
    def fetch(self):
        # submit all buffers in strict mode
        if self._strflg:
            tmp_dtgram = copy.deepcopy(self._dtgram)
            for buffer in self._buffer.values():
                tmp_dtgram += self.submit(buffer)
            return tmp_dtgram
        return self._dtgram

    # return datagram index
    def index(self, pkt_num):
        for counter, datagram in enumerate(self.datagram):
            if pkt_num in datagram.index:
                return counter
        return None

    # run automatically
    def run(self, packets):
        for packet in packets:
            if not isinstance(packet, dict):
                raise AssertionError
            info = Info(packet)
            self.reassembly(info)

    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __new__(cls, *, strict=False):
        self = super().__new__(cls)
        return self

    def __init__(self, *, strict=False):
        self._strflg = strict   # stirct mode flag
        self._buffer = dict()   # buffer field
        self._dtgram = tuple()  # reassembled datagram

    def __call__(self, packet_dict):
        if not isinstance(packet_dict, dict):
            raise AssertionError
        info = Info(packet_dict)
        self.reassembly(info)
