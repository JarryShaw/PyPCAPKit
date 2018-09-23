# -*- coding: utf-8 -*-
"""root protocol

`pcapkit.ipsuite.protocol` contains `Protocol` only,
which is an abstract base class for all protocol family,
with pre-defined utility arguments and methods of specified
protocols.

"""
import abc
import collections.abc
import enum
import functools
import io
import numbers
import re
import shutil
import string
import struct
import textwrap

import aenum
from pcapkit.corekit.infoclass import Info
from pcapkit.utilities.exceptions import ProtocolNotImplemented, StructError
from pcapkit.utilities.validations import dict_check

__all__ = ['Protocol']

# readable characters' order list
readable = [ord(char) for char in filter(lambda char: not char.isspace(), string.printable)]


@functools.total_ordering
class Protocol:
    """Abstract base class for Internet Protocol Suite.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * data -- bytes, binary packet data if current instance
        * alias -- str, acronym of corresponding protocol

    Methods:
        * index -- return first index of value from a dict
        * pack -- pack integers to bytes

    Utilities:
        * __make__ -- make packet data

    """
    __metaclass__ = abc.ABCMeta

    ##########################################################################
    # Properties.
    ##########################################################################

    # name of current protocol
    @property
    @abc.abstractmethod
    def name(self):
        """Name of current protocol."""
        pass

    # acronym of current protocol
    @property
    def alias(self):
        """Acronym of current protocol."""
        return self.__class__.__name__

    # info dict of current instance
    @property
    def info(self):
        """Info dict of current instance."""
        return Info(self.__args__)

    # binary packet data if current instance
    @property
    def data(self):
        """Binary packet data if current instance."""
        return self.__data__

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def index(cls, name, default=None, *, namespace=None, reversed=False,
              pack=False, size=4, signed=False, lilendian=False):
        """Return first index of name from a dict or enumeration.

        Positional arguments:
            * name -- str / int / IntEnum, item to be indexed
            * default -- int, default value

        Keyword arguments:
            * namespace -- dict / EnumMeta, namespace for item
            * reversed -- bool, if namespace is [str -> int] pairs
            * pack -- bool, if need struct.pack
            * size -- int, buffer size (default is 4)
            * signed -- bool, signed flag (default is False)
            * lilendian -- bool, little-endian flag (default is False)

        """
        if isinstance(name, (enum.IntEnum, aenum.IntEnum)):
            index = name.value
        elif isinstance(name, numbers.Integral):
            index = name
        else:
            try:
                if isinstance(namespace, (enum.EnumMeta, aenum.EnumMeta)):
                    index = namespace[name]
                elif isinstance(namespace, (dict, collections.UserDict, collections.abc.Mapping)):
                    if reversed:
                        index = namespace[name]
                    else:
                        index = {v: k for k, v in namespace.items()}[name]
                else:
                    raise KeyError
            except KeyError:
                if default is None:
                    raise ProtocolNotImplemented('protocol {!r} not implemented'.format(name)) from None
                index = default
        if pack:
            return cls.pack(index, size=size, signed=signed, lilendian=lilendian)
        return index

    @classmethod
    def pack(cls, integer, *, size=1, signed=False, lilendian=False):
        """Pack integers to bytes.

        Positional arguments:
            * integer  -- int, integer to be packed

        Keyword arguments:
            * size  -- int, buffer size (default is 1)
            * signed -- bool, signed flag (default is False)
                           <keyword> True / False
            * lilendian -- bool, little-endian flag (default is False)
                           <keyword> True / False

        Returns:
            * bytes -- packed data upon success

        """
        endian = '<' if lilendian else '>'
        if size == 8:                       # unpack to 8-byte integer (long long)
            kind = 'q' if signed else 'Q'
        elif size == 4:                     # unpack to 4-byte integer (int / long)
            kind = 'i' if signed else 'I'
        elif size == 2:                     # unpack to 2-byte integer (short)
            kind = 'h' if signed else 'H'
        elif size == 1:                     # unpack to 1-byte integer (char)
            kind = 'b' if signed else 'B'
        else:                               # do not unpack
            kind = None

        if kind is None:
            end = 'little' if lilendian else 'big'
            buf = integer.to_bytes(size, end, signed=signed)
        else:
            try:
                fmt = '{}{}'.format(endian, kind)
                buf = struct.pack(fmt, integer)
            except struct.error:
                raise StructError('{}: pack failed'.format(cls.__name__)) from None
        return buf

    ##########################################################################
    # Data models.
    ##########################################################################

    def __new__(cls, args={}, **kwargs):
        self = super().__new__(cls)
        return self

    def __init__(self, args={}, **kwargs):
        if not isinstance(args, Info):
            dict_check(args)

        self.__args__ = collections.defaultdict(lambda: NotImplemented)
        self.__args__.update(args)
        self.__args__.update(kwargs)
        self.__data__ = self.__make__()

    def __bytes__(self):
        return self.__data__

    def __len__(self):
        return len(self.__data__)

    def __iter__(self):
        return iter(self.__data__)

    @classmethod
    def __index__(cls):
        return cls.__name__

    # def __truediv__(self, other):
    #     from pcapkit.ipsuite.packet import Packet
    #     return Packet(other.data, **{self.alias.lower(): })

    def __repr__(self):
        repr_ = "<{} {!r}>".format(self.alias, self.info)
        return repr_

    def __str__(self):
        hexbuf = ' '.join(textwrap.wrap(self.__data__.hex(), 2))
        strbuf = ''.join(chr(char) if char in readable else '.' for char in self.__data__)

        number = shutil.get_terminal_size().columns // 4 - 1
        length = number * 3

        hexlst = textwrap.wrap(hexbuf, length)
        strlst = [buf for buf in iter(functools.partial(io.StringIO(strbuf).read, number), '')]

        str_ = '\n'.join(map(lambda x: '{}    {}'.format(x[0].ljust(length), x[1]), zip(hexlst, strlst)))
        return str_

    @classmethod
    def __eq__(cls, other):
        try:
            flag = issubclass(other, Protocol)
        except TypeError:
            flag = issubclass(type(other), Protocol)

        if isinstance(other, Protocol) or flag:
            return (other.__index__ == cls.__index__)

        try:
            index = cls.__index__()
            if isinstance(index, tuple):
                return any(map(lambda x: re.fullmatch(other, x, re.IGNORECASE), index))
            return bool(re.fullmatch(other, index, re.IGNORECASE))
        finally:
            return False

    @classmethod
    def __lt__(cls, other):
        return NotImplemented

    ##########################################################################
    # Utilities.
    ##########################################################################

    @abc.abstractmethod
    def __make__(self):
        """Make packet data."""
        pass
