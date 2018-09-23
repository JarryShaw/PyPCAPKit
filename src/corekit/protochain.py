# -*- coding: utf-8 -*-
"""protocol chain collection

`pcapkit.corekit.protochain` contains special protocol
collection class `ProtoChain`.

"""
import collections.abc
import contextlib
import numbers
import re

from pcapkit.corekit.infoclass import Info
from pcapkit.utilities.exceptions import (IndexNotFound, IntError,
                                          ProtocolUnbound)
from pcapkit.utilities.validations import int_check, str_check

###############################################################################
# from pcapkit.protocols.protocol import Protocol
###############################################################################

__all__ = ['ProtoChain']


class _ProtoList(collections.abc.Collection):
    """List of protocol classes for ProtoChain."""
    @property
    def data(self):
        return self.__data__

    def __init__(self, data=None, *, base=None):
        self.__data__ = list()

        if data is not None:
            self.__data__.append(data)

        if base is not None:
            if isinstance(base, _ProtoList):
                self.__data__.extend(base.data)
            else:
                self.__data__.extend(base)

    def __len__(self):
        return len(self.__data__)

    def __iter__(self):
        return iter(self.__data__)

    def __contains__(self, x):
        from pcapkit.protocols.protocol import Protocol
        try:
            flag = issubclass(x, Protocol)
        except TypeError:
            flag = issubclass(type(x), Protocol)
        if flag or isinstance(x, Protocol):
            return (x in self.__data__)

        with contextlib.suppress(Exception):
            for data in self.__data__:
                index = data.__index__()
                if isinstance(index, tuple):
                    index = r'|'.join(index)
                if re.fullmatch(index, x, re.IGNORECASE):
                    return True
        return False


class _AliasList(collections.abc.Sequence):
    """List of protocol aliases for ProtoChain"""
    @property
    def data(self):
        return self.__data__

    def __init__(self, data=None, *, base=None):
        self.__data__ = list()

        if data is not None:
            self.__data__.append(data)

        if base is not None:
            if isinstance(base, _ProtoList):
                self.__data__.extend(base.data)
            else:
                self.__data__.extend(base)

    def __len__(self):
        return len(self.__data__)

    def __iter__(self):
        return iter(self.__data__)

    def __getitem__(self, index):
        return self.__data__[index]

    def __reversed__(self):
        return reversed(self.__data__)

    def __contains__(self, x):
        from pcapkit.protocols.protocol import Protocol
        try:
            flag = issubclass(x, Protocol)
        except TypeError:
            flag = issubclass(type(x), Protocol)
        if flag or isinstance(x, Protocol):
            x = x.__index__()
            if isinstance(x, tuple):
                x = r'|'.join(x)

        with contextlib.suppress(Exception):
            for data in self.__data__:
                if re.fullmatch(x, data, re.IGNORECASE):
                    return True
        return False

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
                value = r'|'.join(value)

        with contextlib.suppress(Exception):
            return sum(1 for data in self.__data__ if re.fullmatch(value, data, re.IGNORECASE) is not None)
        return 0
        # return self.__data__.count(value)

    def index(self, value, start=0, stop=None):
        """S.index(value, [start, [stop]]) -> integer -- return first index of value.
           Raises ValueError if the value is not present.

           Supporting start and stop arguments is optional, but
           recommended.
        """
        if start is not None and start < 0:
            start = max(len(self) + start, 0)
        if stop is not None and stop < 0:
            stop += len(self)

        try:
            if not isinstance(start, numbers.Integral):
                start = self.index(start)
            if not isinstance(stop, numbers.Integral):
                stop = self.index(stop)
        except IndexNotFound:
            raise IntError('slice indices must be integers or have an __index__ method') from None

        from pcapkit.protocols.protocol import Protocol
        try:
            flag = issubclass(value, Protocol)
        except TypeError:
            flag = issubclass(type(value), Protocol)
        if flag or isinstance(value, Protocol):
            value = value.__index__()
            if isinstance(value, tuple):
                value = r'|'.join(value)

        try:
            for index, data in enumerate(self.__data__[start:stop]):
                if re.fullmatch(value, data, re.IGNORECASE):
                    return index
        except Exception:
            raise IndexNotFound('{!r} is not in {!r}'.format(value, self.__class__.__name__))
        # return self.__data__.index(value, start, stop)


class ProtoChain(collections.abc.Container):
    """Protocols chain.

    Properties:
        * alias -- tuple, aliases of protocols in chain
        * tuple -- tuple, name of protocols in chain
        * proto -- tuple, lowercase name of protocols in chain
        * chain -- str, chain of protocols seperated by colons

    Methods:
        * index -- same as `index` function of `tuple` type

    Attributes:
        * __alias__ -- list, alias of protocols in chain
        * __proto__ -- list, name of protocols in chain

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def proto(self):
        return self.__proto__

    @property
    def alias(self):
        return self.__alias__

    @property
    def tuple(self):
        return tuple(proto.__name__ for proto in self.__proto__.data)

    @property
    def chain(self):
        return self.__str__()

    ##########################################################################
    # Methods.
    ##########################################################################

    def index(self, value, start=None, stop=None):
        """Return first index of value."""
        return self.__alias__.index(value, start, stop)

    def count(self, value):
        """Return number of occurrences of value."""
        return self.__alias__.count(value)

    ##########################################################################
    # Data modules.
    ##########################################################################

    def __init__(self, proto=None, alias=None, *, basis=None):
        if alias is None and proto is not None:
            alias = getattr(proto, '__name__', type(proto).__name__)

        if basis is None:
            basis = Info(proto=None, alias=None)

        self.__proto__ = _ProtoList(proto, base=basis.proto)
        self.__alias__ = _AliasList(alias, base=basis.alias)

    def __repr__(self):
        return "ProtoChain({})".format(', '.join(self.__proto__.data))

    def __str__(self):
        # for (i, proto) in enumerate(self.__alias__):
        #     if proto is None or proto == 'Raw':
        #         return ':'.join(self.__alias__[:i])
        return ':'.join(self.__alias__.data)

    # def __getitem__(self, key):
    #     if isinstance(key, slice):
    #         start = key.start
    #         stop = key.stop
    #         step = key.step

    #         if step is not None:
    #             raise ProtocolUnbound('protocol slice unbound')
    #         if not isinstance(start, numbers.Integral):
    #             start = self.index(start)
    #         if not isinstance(stop, numbers.Integral):
    #             stop = self.index(stop)

    #         int_check(start, stop, step)
    #         key = slice(start, stop, step)
    #     elif isinstance(key, numbers.Integral):
    #         key = key
    #     else:
    #         key = self.index(key)
    #     return (self.__proto__[key], self.__alias__[key])

    def __contains__(self, name):
        return ((name in self.__proto__) or (name in self.__alias__))
