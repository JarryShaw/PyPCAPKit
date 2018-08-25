# -*- coding: utf-8 -*-
"""protocol chain collection

`pcapkit.corekit.protochain` contains special protocol
collection class `ProtoChain`.

"""
import collections.abc
import numbers
import re

from pcapkit.utilities.exceptions import IndexNotFound, ProtocolUnbound
from pcapkit.utilities.validations import int_check, str_check


###############################################################################
# from pcapkit.protocols.protocol import Protocol
###############################################################################


__all__ = ['ProtoChain']


class ProtoChain(collections.abc.Sequence):
    """Protocols chain.

    Properties:
        * alias -- tuple, aliases of protocols in chain
        * tuple -- tuple, name of protocols in chain
        * proto -- tuple, lowercase name of protocols in chain
        * chain -- str, chain of protocols seperated by colons

    Methods:
        * index -- same as `index` function of `tuple` type

    Attributes:
        * __damn__ -- list, aliase of protocols in chain
        * __data__ -- list, name of protocols in chain

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self):
        return tuple(self.__damn__)

    @property
    def tuple(self):
        return tuple(self.__data__)

    @property
    def proto(self):
        # proto = list()
        # for name in self.__data__:
        #     proto.append(str(name).lower().replace('none', 'raw'))
        return tuple(map(lambda name: name.lower(), self.__data__))

    @property
    def chain(self):
        return self.__str__()

    ##########################################################################
    # Methods.
    ##########################################################################

    def index(self, value, start=None, stop=None):
        """S.index(value, [start, [stop]]) -> integer -- return first index of value.
           Raises ValueError if the value is not present.
           
           Supporting start and stop arguments is optional, but
           recommended.

        """
        start = start or 0
        stop = stop or len(self.__data__)

        from pcapkit.protocols.protocol import Protocol
        try:
            flag = issubclass(value, Protocol)
        except TypeError:
            flag = issubclass(type(value), Protocol)
        if flag or isinstance(value, Protocol):
            value = value.__index__()
            if isinstance(value, tuple):
                value = r'|'.join(map(re.escape, value))

        if isinstance(start, str):
            start = self.index(start)
        if isinstance(stop, str):
            stop = self.index(stop)

        str_check(value)
        int_check(start, stop)

        data = self.__data__[start:stop]
        damn = self.__damn__[start:stop]

        for index, zipped in enumerate(zip(data, damn)):
            if any(map(lambda x: re.fullmatch(value, x, re.IGNORECASE), zipped)):
                return index
        raise IndexNotFound(f"'{value}' not in ProtoChain")

        # try:
        #     return self.proto.index(name, start, stop)
        # except ValueError:
        #     raise IndexNotFound(f"'{name}' not in ProtoChain")

    def count(self, value):
        """S.count(value) -> integer -- return number of occurrences of value"""
        from pcapkit.protocols.protocol import Protocol
        try:
            flag = issubclass(value, Protocol)
        except TypeError:
            flag = issubclass(type(value), Protocol)
        if flag or isinstance(value, Protocol):
            value = value.__index__()
            if isinstance(value, tuple):
                value = r'|'.join(map(re.escape, value))

        count = 0
        for zipped in zip(self.__data__, self.__damn__):
            if any(map(lambda x: re.fullmatch(value, x, re.IGNORECASE), zipped)):
                count += 1
        return count

    ##########################################################################
    # Data modules.
    ##########################################################################

    def __init__(self, proto, other=None, alias=None):
        alias = alias or proto

        self.__data__ = [proto]
        self.__damn__ = [alias]

        if other is not None:
            self.__data__.extend(other.tuple)
            self.__damn__.extend(other.alias)

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

            if step is not None:
                raise ProtocolUnbound('protocol slice unbound')
            if not isinstance(start, numbers.Integral):
                start = self.index(start)
            if not isinstance(stop, numbers.Integral):
                stop = self.index(stop)

            int_check(start, stop, step)
            key = slice(start, stop, step)
        elif isinstance(key, numbers.Integral):
            key = key
        else:
            key = self.index(key)
        return (self.__data__[key], self.__damn__[key])

    def __iter__(self):
        return iter(zip(self.__data__, self.__damn__))

    def __len__(self):
        return len(self.__data__)

    def __contains__(self, name):
        from pcapkit.protocols.protocol import Protocol
        try:
            flag = issubclass(value, Protocol)
        except TypeError:
            flag = issubclass(type(value), Protocol)
        if flag or isinstance(value, Protocol):
            name = name.__index__()
            if isinstance(name, tuple):
                name = r'|'.join(map(re.escape, temp))

        for zipped in zip(self.__data__, self.__damn__):
            if any(map(lambda x: re.fullmatch(name, x, re.IGNORECASE), zipped)):
                return True
        return False

        # if isinstance(name, tuple):
        #     for item in name:
        #         flag = (item.lower() in self.proto)
        #         if flag:    break
        #     return flag
        # if isinstance(name, str):
        #     name = name.lower()
        # return (name in self.proto)

    def __reversed__(self):
        return reversed(zip(self.__data__, self.__damn__))

    ##########################################################################
    # Utilities.
    ##########################################################################

    def __extend__(self, *args):
        def __update__(list_, map_):
            list_.reverse()
            list_.extend(map_)
            list_.reverse()
        filtered = filter(None, reversed(args))
        __update__(self.__data__, map(lambda x: x[0], filtered))
        __update__(self.__damn__, map(lambda x: x[1], filtered))
