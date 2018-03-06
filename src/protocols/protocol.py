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


from jspcap.utilities import seekset, Info, ProtoChain
from jspcap.exceptions import BoolError, BytesError
from jspcap.validations import bool_check, int_check


__all__ = ['Protocol']


ABCMeta = abc.ABCMeta
abstractmethod = abc.abstractmethod
abstractproperty = abc.abstractproperty


class Protocol:
    """Abstract base class for all protocol family.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor

    """
    __metaclass__ = ABCMeta

    ##########################################################################
    # Properties.
    ##########################################################################

    # name of current protocol
    @abstractproperty
    def name(self):
        pass

    # info dict of current instance
    @property
    def info(self):
        return self._info

    # header length of current protocol
    @abstractproperty
    def length(self):
        pass

    # name of next layer protocol
    @property
    def protocol(self):
        try:
            return self._protos[1]
        except IndexError:
            return None

    # protocol chain of current instance
    @property
    def protochain(self):
        return self._protos

    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __new__(cls, *args, **kwargs):
        self = super().__new__(cls)
        return self

    def __repr__(self):
        name = self.__class__.__name__
        repr_ = f"<class 'protocol.{name}'>"
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
        file_ = copy.deepcopy(self._file)
        file_.seek(os.SEEK_SET)
        return iter(file_)

    # def __next__(self):
    #     next_ = self._file.read(1)
    #     if next_:
    #         return next_
    #     else:
    #         self._file.seek(os.SEEK_SET)
    #         raise StopIteration

    def __getitem__(self, key):
        return self._info[key]

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size):
        """Read next layer protocol type.

        Keyword arguments:
            size  -- int, buffer size

        """
        return None

    def _read_fileng(self, *args, **kwargs):
        """Read file buffer."""
        return self._file.read(*args, **kwargs)

    def _read_unpack(self, size=1, *, sign=False, lilendian=False):
        """Read bytes and unpack for integers.

        Keyword arguments:
            size       -- int, buffer size (default is 1)
            sign       -- bool, signed flag (default is False)
                           <keyword> True / False
            lilendian  -- bool, little-endian flag (default is False)
                           <keyword> True / False

        """
        endian = '<' if lilendian else '>'
        if size == 8:   kind = 'q' if sign else 'Q' # unpack to 8-byte integer (long long)
        elif size == 4: kind = 'i' if sign else 'I' # unpack to 4-byte integer (int / long)
        elif size == 2: kind = 'h' if sign else 'H' # unpack to 2-byte integer (short)
        elif size == 1: kind = 'b' if sign else 'B' # unpack to 1-byte integer (char)
        else:           kind = None                 # do not unpack

        if kind is None:
            buf = self._file.read(size)
        else:
            try:
                fmt = f'{endian}{kind}'
                mem = self._file.read(size)
                buf = struct.unpack(fmt, mem)[0]
            except struct.error:
                return None
        return buf

    def _read_binary(self, size=1):
        """Read bytes and convert into binaries.

        Keyword arguments:
            size  -- int, buffer size (default is 1)

        """
        bin_ = ''
        for _ in range(size):
            byte = self._file.read(1)
            bin_ += bin(ord(byte))[2:].zfill(8)
        return bin_

    def _decode_next_layer(self, dict_, proto=None, length=None):
        """Decode next layer protocol.

        Keyword arguments:
            dict_ -- dict, info buffer
            proto -- str, next layer protocol name
            length -- int, valid (not padding) length

        """
        next_ = self._import_next_layer(proto, length)

        # make next layer protocol name
        name_ = str(proto  or 'Raw').lower()

        # write info and protocol chain into dict
        dict_[name_] = next_[0]
        self._protos = ProtoChain(proto, next_[1])
        return dict_

    def _import_next_layer(self, proto, length=None):
        """Import next layer extractor.

        Keyword arguments:
            proto -- str, next layer protocol name
            length -- int, valid (not padding) length

        """
        data = file_.read(*[length]) or None
        return data, None
