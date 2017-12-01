#!/usr/bin/python3
# -*- coding: utf-8 -*-


import abc


# Internet Protocol
# Analyser for IP header


from .internet import Internet
from ..protocol import Info


abstractmethod = abc.abstractmethod
abstractproperty = abc.abstractproperty


class IP(Internet):

    __all__ = ['name', 'info', 'length', 'src', 'dst', 'layer', 'protocol']

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

    def __init__(self, _file):
        self._file = _file
        self._info = Info(self.read_ip())

    def __len__(self):
        return self._info.hdr_len

    @abstractmethod
    def __length_hint__(self):
        pass

    ##########################################################################
    # Utilities.
    ##########################################################################

    @abstractmethod
    def read_ip(self):
        pass

    @abstractmethod
    def _read_ip_addr(self):
        pass

    @abstractmethod
    def _read_ip_proto(self):
        pass

    # def _read_ip_options(self):
    #     pass
