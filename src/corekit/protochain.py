# -*- coding: utf-8 -*-
"""protocol chain collection

`jspcap.corekit.protochain` contains special protocol
collection class `ProtoChain`.

"""
import numbers

from jspcap.utilities.exceptions import IndexNotFound
from jspcap.utilities.validations import int_check

###############################################################################
# from jspcap.protocols.protocol import Protocol
###############################################################################


__all__ = ['ProtoChain']


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
