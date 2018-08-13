# -*- coding: utf-8 -*-
"""root protocol

`pcapkit.protocols.protocol` contains `Protocol` only,
which is an abstract base clss for all protocol family,
with pre-defined utility arguments and methods of specified
protocols.

"""
import abc
import ast
import copy
import functools
import io
import numbers
import os
import re
import string
import struct
import sys
import textwrap
import urllib

import chardet

from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.utilities.decorators import beholder, seekset
from pcapkit.utilities.exceptions import BoolError, BytesError, StructError
from pcapkit.utilities.validations import bool_check, int_check

###############################################################################
# from pcapkit.protocols.raw import Raw
###############################################################################


__all__ = ['Protocol', 'NoPayload']


# readable characters' order list
readable = [ ord(char) for char in filter(lambda char: not char.isspace(), string.printable) ]


# abstract base class utilities
ABCMeta = abc.ABCMeta
abstractmethod = abc.abstractmethod
abstractproperty = abc.abstractproperty


class Protocol:
    """Abstract base class for all protocol family.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * length -- int, header length of corresponding protocol
        * payload -- Protocol, payload of current instance
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * decode -- decode bytes into str
        * unquote -- unquote URLs into readable format

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _next -- Protocol, payload of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _read_packet -- read raw packet data
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor
        * _cheak_term_threshold -- check if reached termination threshold

    """
    __layer__ = None
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
        return self._info

    # header length of current protocol
    @abstractproperty
    def length(self):
        """Header length of current protocol."""
        pass

    # payload of current instance
    @property
    def payload(self):
        """Payload of current instance."""
        return self._next
    
    # name of next layer protocol
    @property
    def protocol(self):
        """Name of next layer protocol."""
        try:
            return self._protos[1]
        except IndexError:
            return None

    # protocol chain of current instance
    @property
    def protochain(self):
        """Protocol chain of current instance."""
        return self._protos

    ##########################################################################
    # Methods.
    ##########################################################################

    @staticmethod
    def decode(byte, *, encoding=None, errors='strict'):
        """Decode bytes into str."""
        charset = encoding or chardet.detect(byte)['encoding']
        try:
            return byte.decode(charset or 'utf-8', errors=errors)
        except UnicodeError:
            return r''.join( chr(char) for char in byte )

    @staticmethod
    def unquote(url, *, encoding='utf-8', errors='replace'):
        """Unquote URLs into readable format."""
        try:
            return urllib.parse.unquote(url, encoding=encoding, errors=errors)
        except UnicodeError:
            str_ = url.replace('%', '\\x')
            return ast.literal_eval(f'r"{str_}"')

    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __new__(cls, file=None, *args, **kwargs):
        self = super().__new__(cls)

        self._onerror = kwargs.pop('error', False)
        self._exlayer = kwargs.pop('layer', str())
        self._exproto = kwargs.pop('protocol', str())

        self._seekset = (file or io.BytesIO()).tell()
        self._sigterm = self._check_term_threshold()

        return self

    def __repr__(self):
        repr_ = f"<{self.alias} {self._info}>"
        return repr_

    @seekset
    def __str__(self):
        bytes_ = self._read_fileng()

        hexbuf = ' '.join(textwrap.wrap(bytes_.hex(), 2))
        strbuf = ''.join( chr(char) if char in readable else '.' for char in bytes_ )

        number = os.get_terminal_size().columns // 4 - 1
        length = number * 3

        hexlst = textwrap.wrap(hexbuf, length)
        strlst = [ buf for buf in iter(functools.partial(io.StringIO(strbuf).read, number), '') ]

        str_ = '\n'.join(map(lambda x: f'{x[0].ljust(length)}    {x[1]}', zip(hexlst, strlst)))
        return str_

    @seekset
    def __bytes__(self):
        bytes_ = self._read_fileng()
        return bytes_

    @seekset
    def __len__(self):
        """Total length of correspoding protocol."""
        return len(self._read_fileng())

    @abstractmethod
    def __length_hint__(self):
        pass

    def __iter__(self):
        file = copy.deepcopy(self._file)
        file.seek(os.SEEK_SET)
        return iter(file)

    # def __next__(self):
    #     next_ = self._file.read(1)
    #     if next_:
    #         return next_
    #     else:
    #         self._file.seek(os.SEEK_SET)
    #         raise StopIteration

    def __getitem__(self, key):
        return self._info[key]

    @classmethod
    def __index__(cls):
        return cls.__name__

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size):
        """Read next layer protocol type.

        Positional arguments:
            * size  -- int, buffer size

        Returns:
            * [upon success] str -- name of next layer protocol
            * [upon failure] None

        """
        return None

    def _read_fileng(self, *args, **kwargs):
        """Read file buffer."""
        return self._file.read(*args, **kwargs)

    def _read_unpack(self, size=1, *, signed=False, lilendian=False, quiet=False):
        """Read bytes and unpack for integers.

        Positional arguments:
            * size  -- int, buffer size (default is 1)

        Keyword arguments:
            * signed -- bool, signed flag (default is False)
                           <keyword> True / False
            * lilendian -- bool, little-endian flag (default is False)
                           <keyword> True / False
            * quiet -- bool, quiet (no exception) flag (default is False)
                           <keyword> True / False

        Returns:
            * int -- unpacked data upon success

        """
        endian = '<' if lilendian else '>'
        if size == 8:   kind = 'q' if signed else 'Q'   # unpack to 8-byte integer (long long)
        elif size == 4: kind = 'i' if signed else 'I'   # unpack to 4-byte integer (int / long)
        elif size == 2: kind = 'h' if signed else 'H'   # unpack to 2-byte integer (short)
        elif size == 1: kind = 'b' if signed else 'B'   # unpack to 1-byte integer (char)
        else:           kind = None                     # do not unpack

        if kind is None:
            mem = self._file.read(size)
            end = 'little' if lilendian else 'big'
            buf = int.from_bytes(mem, end, signed=signed)
        else:
            try:
                fmt = f'{endian}{kind}'
                mem = self._file.read(size)
                buf = struct.unpack(fmt, mem)[0]
            except struct.error:
                if quiet:
                    return None
                else:
                    raise StructError(f'{self.__class__.__name__}: unpack failed') from None
        return buf

    def _read_binary(self, size=1):
        """Read bytes and convert into binaries.

        Positional arguments:
            * size  -- int, buffer size (default is 1)

        Returns:
            * str -- binary bits (0/1)

        """
        bin_ = ''
        for _ in range(size):
            byte = self._file.read(1)
            bin_ += bin(ord(byte))[2:].zfill(8)
        return bin_

    @seekset
    def _read_packet(self, length=None, *, header=None, payload=None, discard=False):
        """Read raw packet data.

        Positional arguments:
            * length -- int, length of the packet

        Keyword arguments:
            * header -- int, length of the packet header
            * payload -- int, length of the packet payload
            * discard -- bool, flag if discard header data (False in default)

        Returns:
            * [if header omits] bytes -- whole packet data
            * [if discard set True] bytes -- packet body only
            * dict -- header and payload data
                |-- 'header' -- bytes, packet header
                |-- 'payload' -- bytes, packet payload

        """
        if header is not None:
            header = self._read_fileng(header)
            payload = self._read_fileng(*[payload])
            if discard:
                return payload
            return dict(header=header, payload=payload)
        return self._read_fileng(*[length])

    def _decode_next_layer(self, dict_, proto=None, length=None):
        """Decode next layer protocol.

        Positional arguments:
            * dict_ -- dict, info buffer
            * proto -- str, next layer protocol name
            * length -- int, valid (not padding) length

        Returns:
            * dict -- current protocol with next layer extracted

        """
        if self._onerror:
            flag, next_ = beholder(self._import_next_layer)(self, proto, length)
        else:
            flag, next_ = self._import_next_layer(proto, length)
        info, chain, alias = next_.info, next_.protochain, next_.alias

        # make next layer protocol name
        if flag:
            if proto is None and chain:
                layer = chain.alias[0].lower()
                proto, chain = chain.tuple[0], None
            else:
                layer = str(alias or proto or 'Raw').lower()
        else:
            layer, proto = 'raw', 'Raw'

        # write info and protocol chain into dict
        dict_[layer] = info
        self._next = next_
        self._protos = ProtoChain(proto, chain, alias)
        return dict_

    def _import_next_layer(self, proto, length=None):
        """Import next layer extractor.

        Positional arguments:
            * proto -- str, next layer protocol name
            * length -- int, valid (not padding) length

        Returns:
            * bool -- flag if extraction of next layer succeeded
            * Protocol -- instance of next layer

        """
        from pcapkit.protocols.raw import Raw
        next_ = Raw(io.BytesIO(self._read_fileng(length)), length,
                    layer=self._exlayer, protocol=self._exproto)
        return True, next_

    def _check_term_threshold(self):
        """Check if reached termination threshold."""
        index = self.__index__()
        layer = self.__layer__ or ''

        pattern = '|'.join(index) if isinstance(index, tuple) else index
        iterable = self._exproto if isinstance(self._exproto, tuple) else (self._exproto,)

        layer_match = re.fullmatch(layer, self._exlayer, re.IGNORECASE)
        protocol_match = filter(lambda string: re.fullmatch(pattern, string, re.IGNORECASE), iterable)

        return bool(list(protocol_match) or layer_match)


class NoPayload(Protocol):
    """This class implements no-payload protocol.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol

    Methods:
        * decode_bytes -- try to decode bytes into str
        * decode_url -- decode URLs into Unicode
        * read_raw -- read raw packet data

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _read_packet -- read raw packet data

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    # name of current protocol
    @property
    def name(self):
        """Name of current protocol."""
        return 'Null'

    # header length of current protocol
    @property
    def length(self):
        """DEPRECATED"""
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'length'")

    # name of next layer protocol
    @property
    def protocol(self):
        """DEPRECATED"""
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protocol'")

    ##########################################################################
    # Data models.
    ##########################################################################

    def __new__(cls, *args, **kwargs):
        self = super().__new__(cls)
        return self

    def __init__(self, *args, **kwargs):
        self._next = self
        self._info = Info()
        self._file = io.BytesIO()
        self._protos = NotImplemented

    def __length_hint__(self):
        pass

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _decode_next_layer(self, dict_, proto=None, length=None):
        """Deprecated."""
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_decode_next_layer'")

    def _import_next_layer(self, proto, length):
        """Deprecated."""
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_import_next_layer'")

