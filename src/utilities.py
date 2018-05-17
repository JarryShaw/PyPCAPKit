# -*- coding: utf-8 -*-
"""utility functions and classes

`jspcap.utilities` contains several useful functions and
classes which are fundations of `jspcap`, including
decorater function `seekset` and `seekset_ng`, 
dict-like class `Info`, tuple-like class `VersionInfo`,
and special class `ProtoChain`.

"""
import copy
import functools
import io
import numbers
import os
import re


# Utility Functions & Classes
# Several useful functions & classes


from jspcap.exceptions import IndexNotFound, UnsupportedCall
from jspcap.validations import dict_check, int_check
# from jspcap.analyser import Analysis
# from jspcap.protocols.protocol import Protocol
# from jspcap.protocols.raw import Raw


__all__ = [
    'seekset', 'seekset_ng',
    'beholder', 'beholder_ng',
    'Info', 'VersionInfo',
    'ProtoChain'
]


# # protocol name replace
# _NAME_REPLACE = {
#     '802.1q'    : 'ctag',
#     'http/1.0'  : 'httpv1',
#     'http/1.1'  : 'httpv1',
#     'http/2'    : 'httpv2',
# }


def seekset(func):
    """Read file from start then set back to original."""
    @functools.wraps(func)
    def seekcur(self, *args, **kw):
        seek_cur = self._file.tell()
        self._file.seek(os.SEEK_SET)
        return_ = func(self, *args, **kw)
        self._file.seek(seek_cur, os.SEEK_SET)
        return return_
    return seekcur


def seekset_ng(func):
    """Read file from start then set back to original."""
    @functools.wraps(func)
    def seekcur(file, *args, **kw):
        seek_cur = file.tell()
        file.seek(os.SEEK_SET)
        return_ = func(file, *args, **kw)
        file.seek(seek_cur, os.SEEK_SET)
        return return_
    return seekcur


def beholder(func):
    """Behold extraction procedure."""
    @functools.wraps(func)
    def behold(self, proto, length, *args, **kwargs):
        seek_cur = self._file.tell()
        try:
            return func(self, proto, length, *args, **kwargs)
        except Exception as error:
            self._file.seek(seek_cur, os.SEEK_SET)
            from jspcap.protocols.raw import Raw
            next_ = Raw(io.BytesIO(self._read_fileng(length)), length, error=str(error))
            return False, next_.info, next_.protochain, next_.alias
    return behold


def beholder_ng(func):
    """Behold analysis procedure."""
    @functools.wraps(func)
    def behold(file, length, *args, **kwargs):
        seek_cur = file.tell()
        try:
            return func(file, length, *args, **kwargs)
        except Exception as error:
            from jspcap.analyser import Analysis
            from jspcap.protocols.raw import Raw

            file.seek(seek_cur, os.SEEK_SET)

            raw = Raw(file, length, error=str(error))
            return Analysis(raw.info, raw.protochain, raw.alias)
    return behold


class Info(dict):
    """Turn dictionaries into object-like instances.

    Methods:
        * infotodict -- reverse Info object into dict type

    Notes:
        * Info objects inherit from `dict` type
        * Info objects are iterable, and support all functions as `dict`
        * Info objects are one-time-modeling, thus cannot set or delete
            attributes after initialisation

    """
    def __new__(cls, dict_=None, **kwargs):
        def __read__(dict_):
            __dict__ = dict()
            for (key, value) in dict_.items():
                if isinstance(value, dict):
                    __dict__[key] = Info(value)
                else:
                    # if isinstance(key, str):
                    #     key = re.sub('\W', '_', key)
                    __dict__[key] = value
            return __dict__

        self = super().__new__(cls)
        if dict_ is not None:
            if isinstance(dict_, Info):
                self = copy.deepcopy(dict_)
            else:
                dict_check(dict_)
                self.__dict__.update(__read__(dict_))

        self.__dict__.update(__read__(kwargs))
        return self

    def __repr__(self):
        temp = list()
        for (key, value) in self.__dict__.items():
            temp.append(f'{key}={value}')
        args = ', '.join(temp)
        return f'Info({args})'

    __str__ = __repr__

    def __iter__(self):
        return iter(self.__dict__)

    def __getitem__(self, key):
        return self.__dict__[key]

    def __contains__(self, name):
        return (name in self.__dict__)

    def __setattr__(self, name, value):
        raise UnsupportedCall("can't set attribute")

    def __delattr__(self, name):
        raise UnsupportedCall("can't delete attribute")

    def infotodict(self):
        dict_ = dict()
        for (key, value) in self.__dict__.items():
            if isinstance(value, Info):
                dict_[key] = value.infotodict()
            elif isinstance(value, (tuple, list)):
                temp = list()
                for item in value:
                    if isinstance(item, Info):
                        temp.append(item.infotodict())
                    else:
                        temp.append(item)
                dict_[key] = value.__class__(temp)
            else:
                dict_[key] = value
        return dict_


class VersionInfo:
    """VersionInfo alikes `sys.version_info`."""
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


class ProtoChain:
    """Protocols chain.

    Properties:
        * alias -- tuple, aliases of protocols in chain
        * tuple -- tuple, name of protocols in chain
        * proto -- tuple, lowercase name of protocols in chain
        * chain -- str, chain of protocols seperated by colons

    Methods:
        * index -- same as `index` function of `tuple` type

    Attributes:
        * __damn__ -- tuple, aliase of protocols in chain
        * __data__ -- tuple, name of protocols in chain

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self):
        return self.__damn__

    @property
    def tuple(self):
        return self.__data__

    @property
    def proto(self):
        proto = list()
        for name in self.__data__:
            proto.append(str(name).lower().replace('none', 'raw'))
        return tuple(proto)

    @property
    def chain(self):
        return self.__str__()

    ##########################################################################
    # Methods.
    ##########################################################################

    def index(self, name, start=None, stop=None):
        try:
            start = start or 0
            stop = stop or len(self.tuple)

            if isinstance(name, str):
                name = name.lower()
            if isinstance(start, str):
                start = self.index(start)
            if isinstance(stop, str):
                stop = self.index(stop)
            int_check(start, stop)
            return self.proto.index(name, start, stop)
        except ValueError:
            raise IndexNotFound(f"'{name}' not in ProtoChain")

    ##########################################################################
    # Data modules.
    ##########################################################################

    def __init__(self, proto, other=None, alias=None):
        alias = alias or proto
        if other is None:
            self.__data__ = (proto,)
            self.__damn__ = (alias,)
        else:
            self.__data__ = (proto,) + other.tuple
            self.__damn__ = (alias,) + other.alias

    def __repr__(self):
        repr_ = ', '.join(self.proto)
        return f'ProtoChain({repr_})'

    def __str__(self):
        for (i, proto) in enumerate(self.__damn__):
            if proto is None or proto == 'Raw':
                return ':'.join(self.__damn__[:i])
        return ':'.join(self.__damn__)

    def __getitem__(self, key):
        if isinstance(key, slice):
            start = key.start
            stop = key.stop
            step = key.step

            if not isinstance(start, numbers.Number):
                start = self.index(start)
            if not isinstance(stop, numbers.Number):
                stop = self.index(stop)
            int_check(start, stop, step)
            key = slice(start, stop, step)
        elif isinstance(key, numbers.Number):
            key = key
        else:
            key = self.index(key)
        return self.__data__[key]

    def __iter__(self):
        return iter(self.__damn__)

    def __contains__(self, name):
        from jspcap.protocols.protocol import Protocol
        if isinstance(name, type) and issubclass(name, Protocol):
            name = name.__index__()
        if isinstance(name, tuple):
            for item in name:
                flag = (item.lower() in self.proto)
                if flag:    break
            return flag
        if isinstance(name, str):
            name = name.lower()
        return (name in self.proto)
