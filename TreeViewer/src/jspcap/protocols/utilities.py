#!/usr/bin/python3
# -*- coding: utf-8 -*-


import copy
import numbers
import os


# Utility Functions & Classes
# Several useful functions & classes


__all__ = ['seekset', 'Info', 'ProtoChain']


def seekset(func):
    """Rean file from start then set back to original."""
    def seekcur(self, *args, **kw):
        seek_cur = self._file.tell()
        self._file.seek(os.SEEK_SET)
        return_ = func(self, *args, **kw)
        self._file.seek(seek_cur, os.SEEK_SET)
        return return_
    return seekcur


class Info(dict):
    """Turn dictionaries into object-like instances."""

    def __new__(cls, dict_=None, **kwargs):
        self = super().__new__(cls, **kwargs)

        if dict_ is None:
            return self

        if isinstance(dict_, Info):
            self = copy.deepcopy(dict_)
            return self

        for key in dict_:
            if isinstance(dict_[key], Info):
                self.__dict__[key] = dict_[key]
            elif isinstance(dict_[key], dict):
                self.__dict__[key] = Info(dict_[key])
            else:
                if isinstance(key, str):
                    key = key.replace('-', '_')
                self.__dict__[key] = dict_[key]

        return self

    def __repr__(self):
        list_ = []
        for (key, value) in self.__dict__.items():
            str_ = '{key}={value}'.format(key=key, value=str(value))
            list_.append(str_)
        repr_ = 'Info(' + ', '.join(list_) + ')'
        return repr_

    __str__ = __repr__

    def __getitem__(self, key):
        return self.__dict__[key]

    def __contains__(self, name):
        return (name in self.__dict__)

    def __setattr__(self, name, value):
        raise AttributeError('can\'t set attribute')

    def __delattr__(self, name):
        raise AttributeError('can\'t delete attribute')

    def infotodict(self):
        dict_ = {}
        for key in self.__dict__:
            if isinstance(self.__dict__[key], Info):
                dict_[key] = self.__dict__[key].infotodict()
            else:
                dict_[key] = self.__dict__[key]
        return dict_


class ProtoChain(tuple):
    """Protocols chain."""

    __all__ = ['tuple', 'proto', 'chain']

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def tuple(self):
        return self._tuple

    @property
    def proto(self):
        list_ = []
        tuple_ = copy.deepcopy(self._tuple)
        for proto in tuple_:
            proto = None if proto is None else proto.lower()
            list_.append(proto)
        protos = tuple(list_)
        return protos

    @property
    def chain(self):
        return self.__str__()

    ##########################################################################
    # Data modules.
    ##########################################################################

    def __new__(cls, proto, other=None):
        self = super().__new__(cls)
        return self

    def __init__(self, proto, other=None):
        if other is None:
            self._tuple = (proto,)
        else:
            self._tuple = (proto,) + other.tuple

    def __repr__(self):
        proto = ', '.join(self.proto)
        repr_ = 'ProtoChain({})'.format(proto)
        return repr_

    def __str__(self):
        for (i, proto) in enumerate(self._tuple):
            if proto is None:
                return ':'.join(self._tuple[:i])
        return ':'.join(self._tuple)

    def __index__(self, name, start=None, stop=None):
        try:
            start = start or 0
            stop = stop or -1

            if isinstance(name, str):
                name = name.lower()
            if isinstance(start, str):
                start = self.index(start)
            if isinstance(stop, str):
                stop = self.index(stop)
            return self.proto.index(name, start, stop)
        except ValueError:
            raise ValueError
        except TypeError:
            raise TypeError

    def __getitem__(self, key):
        try:
            if isinstance(key, slice):
                start = key.start
                stop = key.stop
                step = key.step

                if not isinstance(start, numbers.Number):
                    start = self.index(start)
                if not isinstance(stop, numbers.Number):
                    stop = self.index(stop)
                if not isinstance(step, numbers.Number):
                    step = self.index(step)
                key = slice(start, stop, step)
            else:
                key = self.index(key)
            return self._tuple[key]
        except (ValueError, IndexError):
            raise IndexError
        except TypeError:
            raise TypeError

    def __iter__(self):
        return (name for name in self._tuple)

    def __contains__(self, name):
        if isinstance(name, str):
            name = name.lower()
        return (name in self.proto)

    ##########################################################################
    # Utilities.
    ##########################################################################

    index = __index__
