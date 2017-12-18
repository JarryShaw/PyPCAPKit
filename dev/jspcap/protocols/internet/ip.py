#!/usr/bin/python3
# -*- coding: utf-8 -*-


import abc


# Internet Protocol
# Analyser for IP header


from .internet import Internet
from ..utilities import Info, seekset


abstractmethod = abc.abstractmethod
abstractproperty = abc.abstractproperty


class IP(Internet):

    __all__ = ['name', 'info', 'length', 'src', 'dst', 'layer', 'protocol', 'protochain']

    ##########################################################################
    # Properties.
    ##########################################################################

    @abstractproperty
    def name(self):
        pass

    @property
    def info(self):
        return self._info

    @abstractproperty
    def length(self):
        pass

    @property
    def src(self):
        return self._info.src

    @property
    def dst(self):
        return self._info.dst

    @property
    def layer(self):
        return self.__layer__

    @abstractproperty
    def protocol(self):
        pass

    ##########################################################################
    # Data models.
    ##########################################################################

    @abstractmethod
    def __init__(self, _file):
        self._file = _file
        self._info = Info(self.read_ip())

    @abstractmethod
    def __len__(self):
        pass

    @abstractmethod
    def __length_hint__(self):
        pass

    ##########################################################################
    # Utilities.
    ##########################################################################

    @abstractmethod
    def _read_ip_addr(self):
        pass

    @seekset
    def _read_ip_header(self, length):
        return self._read_fileng(length)
