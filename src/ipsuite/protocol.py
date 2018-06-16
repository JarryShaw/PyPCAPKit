# -*- coding: utf-8 -*-
"""root protocol

`jspcap.ipsuite.protocol` contains `Protocol` only,
which is an abstract base clss for all protocol family,
with pre-defined utility arguments and methods of specified
protocols.

"""
import abc
import struct

from jspcap.corekit.infoclass import Info
from jspcap.utilities.exceptions import ProtocolNotImplemented, StructError
from jspcap.utilities.validations import dict_check


__all__ = ['Protocol']


# abstract base class utilities
ABCMeta = abc.ABCMeta
abstractmethod = abc.abstractmethod
abstractproperty = abc.abstractproperty


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
        * update -- update packet data

    """
    __metaclass__ = ABCMeta

    ##########################################################################
    # Properties.
    ##########################################################################

    # name of current protocol
    @abstractproperty
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
        return Info(self.__dict__)

    # binary packet data if current instance
    @property
    def data(self):
        """Binary packet data if current instance."""
        return self.__data__

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def index(cls, dict_, value, *, pack=False, size=4, lilendian=False):
        """Return first index of value from a dict."""
        try:
            index = list(dict_.keys())[list(dict_.values()).index(value)]
            if pack:
                return cls.pack(index, size=size, lilendian=lilendian)
            return index
        except ValueError:
            raise ProtocolNotImplemented(f'protocol {value} not implemented') from None

    @abstractmethod
    def update(self, **kwargs):
        """Update packet data."""
        pass

    @staticmethod
    def pack(integer, *, size=1, signed=False, lilendian=False):
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
        if size == 8:   kind = 'q' if signed else 'Q'   # unpack to 8-byte integer (long long)
        elif size == 4: kind = 'i' if signed else 'I'   # unpack to 4-byte integer (int / long)
        elif size == 2: kind = 'h' if signed else 'H'   # unpack to 2-byte integer (short)
        elif size == 1: kind = 'b' if signed else 'B'   # unpack to 1-byte integer (char)
        else:           kind = None                     # do not unpack

        if kind is None:
            end = 'little' if lilendian else 'big'
            buf = integer.to_bytes(size, end, signed=signed)
        else:
            try:
                fmt = f'{endian}{kind}'
                buf = struct.pack(fmt, integer)
            except struct.error:
                raise StructError(f'{self.__class__.__name__}: pack failed') from None
        return buf

    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __new__(cls, *args, **kwargs):
        self = super().__new__(cls)
        return self

    def __init__(self, *args, **kwargs):
        self.__dict__ = kwargs
        for arg in args:
            if isinstance(arg, Info):
                arg = arg.infotodict()
            dict_check(arg)
            self.__dict__.update(arg)
        self.update()

    @classmethod
    def __index__(cls):
        return cls.__name__
