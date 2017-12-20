#!/usr/bin/python3
# -*- coding: utf-8 -*-


import abc
import copy
import numbers
import os
import struct
import textwrap


# Abstract Base Class of Protocols
# Pre-define useful arguments and methods of protocols


from .utilities import seekset, Info, ProtoChain
from ..exceptions import BytesError


ABCMeta = abc.ABCMeta
abstractmethod = abc.abstractmethod
abstractproperty = abc.abstractproperty


class Protocol(object):

    __all__ = ['name', 'info', 'length']
    __metaclass__ = ABCMeta

    ##########################################################################
    # Properties.
    ##########################################################################

    # name of current protocol
    @abstractproperty
    def name(self):
        pass

    # info dict of current instance
    @abstractproperty
    def info(self):
        pass

    # header length of current protocol
    @abstractproperty
    def length(self):
        pass

    ##########################################################################
    # Methods.
    ##########################################################################

    def _read_protos(self, size):
        """Read next layer protocol type."""
        pass

    def _read_fileng(self, *args, **kwargs):
        """Read file buffer."""
        return self._file.read(*args, **kwargs)

    def _read_unpack(self, size=1, *, sign=False, lilendian=False):
        """Read bytes and unpack for integers.

        Keyword arguemnts:
            size       -- int, buffer size (default is 1)
            sign       -- bool, signed flag (default is False)
                           <keyword> True / False
            lilendian  -- bool, little-endian flag (default is False)
                           <keyword> True / False

        """
        endian = '<' if lilendian else '>'
        if size == 8:   format_ = 'q' if sign else 'Q'  # unpack to 8-byte integer (long long)
        elif size == 4: format_ = 'i' if sign else 'I'  # unpack to 4-byte integer (int / long)
        elif size == 2: format_ = 'h' if sign else 'H'  # unpack to 2-byte integer (short)
        elif size == 1: format_ = 'b' if sign else 'B'  # unpack to 1-byte integer (char)
        else:           format_ = None                  # do not unpack

        if format_ is None:
            buf = self._file.read(size)
        else:
            try:
                fmt = '{endian}{format}'.format(endian=endian, format=format_)
                buf = struct.unpack(fmt, self._file.read(size))[0]
            except struct.error:
                return None
        return buf

    def _read_binary(self, size=1):
        """Read bytes and convert into binaries.

        Keyword arguemnts:
            size  -- int, buffer size (default is 1)

        """
        bin_ = ''
        for _ in range(size):
            byte = self._file.read(1)
            bin_ += bin(ord(byte))[2:].zfill(8)
        return bin_

    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __new__(cls, _file):
        self = super().__new__(cls)
        return self

    def __repr__(self):
        repr_ = "<class 'protocol.{name}'>".format(name=self.__class__.__name__)
        return repr_

    @seekset
    def __str__(self):
        str_ = ' '.join(textwrap.wrap(self._file.read().hex(), 2))
        return str_

    @seekset
    def __bytes__(self):
        bytes_ = self._file.read()
        return bytes_

    @abstractmethod
    def __len__(self):
        pass

    @abstractmethod
    def __length_hint__(self):
        pass

    def __iter__(self):
        iter_ = copy.deepcopy(self)
        iter_._file.seek(os.SEEK_SET)
        return iter_

    def __next__(self):
        next_ = self._file.read(1)
        if next_:
            return next_
        else:
            self._file.seek(os.SEEK_SET)
            raise StopIteration

    def __getitem__(self, key):
        return self._info[key]

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_next_layer(self, dict_, proto=None, length=None):
        """Extract next layer protocol."""
        next_ = self._import_next_layer(proto, length)

        # make next layer protocol name
        if proto is None:
            proto = ''
        name_ = proto.lower() or 'raw'
        proto = proto or None

        # write info and protocol chain into dict
        dict_[name_] = next_[0]
        self._protos = ProtoChain(proto, next_[1])
        return dict_

    def _import_next_layer(self, proto, length=None):
        """Import next layer extracotr."""
        pass
