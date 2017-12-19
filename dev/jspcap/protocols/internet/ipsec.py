#!/usr/bin/python3
# -*- coding: utf-8 -*-


import abc


# Internet Protocol Security
# Analyser for IPsec header


from .ip import IP
from ..utilities import Info


abstractmethod = abc.abstractmethod


class IPsec(IP):

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def src(self):
        pass

    @property
    def dst(self):
        pass

    ##########################################################################
    # Data models.
    ##########################################################################

    def __new__(cls, _file, length=None, *, version=None):
        self = super().__new__(cls, _file)
        return self

    @abstractmethod
    def __init__(self, _file, length=None, *, version=None):
        self._file = _file
        self._vers = version or 4
        self._info = Info(self.read_ipsec(length))
