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
    def __init__(self, _file, length=None):
        self._file = _file
        self._info = Info(self.read_ip(length))

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
    def _read_ip_seekset(self, ip, hdr_len, raw_len):
        """when fragmented, read payload throughout first."""
        ip['header'] = self._read_fileng(hdr_len)
        ip['raw'] = self._read_fileng(raw_len)
        padding = self._read_fileng()
        if padding:
            ip['padding'] = padding
        return ip
