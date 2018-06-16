# -*- coding: utf-8 -*-
"""version info

`jspcap.corekit.version` contains tuple-like class
`VersionInfo`, which is originally designed alike
`sys.version_info`.

"""
import copy
import functools
import io
import numbers
import os
import re

from jspcap.utilities.exceptions import UnsupportedCall
from jspcap.utilities.validations import int_check


__all__ = ['VersionInfo']


class VersionInfo:
    """VersionInfo is alike `sys.version_info`."""
    @property
    def major(self):
        return self.__vers__[0]

    @property
    def minor(self):
        return self.__vers__[1]

    def __init__(self, vmaj, vmin):
        self.__vers__ = (vmaj, vmin)

    def __str__(self):
        str_ = f'pcap version {self.__vers__[0]}.{self.__vers__[1]}'
        return str_

    def __repr__(self):
        repr_ = f'jspcap.version_info(major={self.__vers__[0]}, minor={self.__vers__[1]})'
        return repr_

    def __getattr__(self, name):
        raise UnsupportedCall("can't get attribute")

    def __setattr__(self, name, value):
        raise UnsupportedCall("can't set attribute")

    def __delattr__(self, name):
        raise UnsupportedCall("can't delete attribute")

    def __getitem__(self, key):
        int_check(key)
        return self.__vers__[key]
