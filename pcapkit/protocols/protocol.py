# -*- coding: utf-8 -*-
"""root protocol

:mod:`pcapkit.protocols.protocol` contains
:class:`~pcapkit.protocols.protocol.Protocol` only, which is
an abstract base class for all protocol family, with pre-defined
utility arguments and methods of specified protocols.

"""
import abc
import collections
import contextlib
import enum
import functools
import importlib
import io
import numbers
import os
import re
import shutil
import string
import struct
import textwrap
import urllib

import aenum
import chardet

from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.utilities.compat import cached_property
from pcapkit.utilities.decorators import beholder, seekset
from pcapkit.utilities.exceptions import (ProtocolNotFound, ProtocolNotImplemented, ProtocolUnbound,
                                          StructError)
from pcapkit.utilities.logging import logger

__all__ = ['Protocol']

# readable characters' order list
readable = [ord(char) for char in filter(lambda char: not char.isspace(), string.printable)]


class Protocol(metaclass=abc.ABCMeta):
    """Abstract base class for all protocol family."""

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Literal['Link', 'Internet', 'Transport', 'Application']: Layer of protocol.
    #: Can be one of ``Link``, ``Internet``, ``Transport`` and ``Application``.
    __layer__ = None

    #: DefaultDict[int, Tuple[str, str]]: Protocol index mapping for decoding next layer,
    #: c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    #: The values should be a tuple representing the module name and class name.
    __proto__ = collections.defaultdict(lambda: ('pcapkit.protocols.raw', 'Raw'))

    ##########################################################################
    # Properties.
    ##########################################################################

    # name of current protocol
    @property
    @abc.abstractmethod
    def name(self):
        """Name of current protocol.

        :rtype: str
        """

    # acronym of current protocol
    @property
    def alias(self):
        """Acronym of current protocol.

        :rtype: str
        """
        return self.__class__.__name__

    # info dict of current instance
    @property
    def info(self):
        """Info dict of current instance.

        :rtype: pcapkit.corekit.infoclass.Info
        """
        return self._info

    # binary packet data if current instance
    @property
    def data(self):
        """Binary packet data of current instance.

        :rtype: bytes
        """
        return self._data

    # header length of current protocol
    @property
    @abc.abstractmethod
    def length(self):
        """Header length of current protocol.

        :rtype: int
        """

    # payload of current instance
    @property
    def payload(self):
        """Payload of current instance.

        :rtype: pcapkit.protocols.protocol.Protocol
        """
        return self._next

    # name of next layer protocol
    @property
    def protocol(self):
        """Name of next layer protocol (if any).

        :rtype: Optional[str]
        """
        with contextlib.suppress(IndexError):
            return self._protos[0]

    # protocol chain of current instance
    @property
    def protochain(self):
        """Protocol chain of current instance.

        :rtype: pcapkit.corekit.protochain.ProtoChain
        """
        return self._protos

    ##########################################################################
    # Methods.
    ##########################################################################

    @abc.abstractmethod
    def read(self, length=None, **kwargs):
        """Read (parse) packet data.

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            dict: Parsed packet data.

        """

    @abc.abstractmethod
    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """

    @staticmethod
    def decode(byte, *, encoding=None, errors='strict'):
        """Decode :obj:`bytes` into :obj:`str`.

        Should decoding failed using ``encoding``, the method will try again decoding
        the :obj:`bytes` as ``'unicode_escape'``.

        Args:
            byte (bytes): Source bytestring.

        Keyword Args:
            encoding (Optional[str]): The encoding with which to decode the :obj:`bytes`.
                If not provided, :mod:`pcapkit` will first try detecting its encoding
                using |chardet|_. The fallback encoding would is **UTF-8**.
            errors (str): The error handling scheme to use for the handling of decoding errors.
                The default is ``'strict'`` meaning that decoding errors raise a
                :exc:`UnicodeDecodeError`. Other possible values are ``'ignore'`` and ``'replace'``
                as well as any other name registered with :func:`codecs.register_error` that
                can handle :exc:`UnicodeDecodeError`.

        Returns:
            str: Decoede string.

        See Also:
            :meth:`bytes.decode`

        .. |chardet| replace:: ``chardet``
        .. _chardet: https://chardet.readthedocs.io

        """
        charset = encoding or chardet.detect(byte)['encoding']
        try:
            return byte.decode(charset or 'utf-8', errors=errors)
        except UnicodeError:
            return byte.decode('unicode_escape')

    @staticmethod
    def unquote(url, *, encoding='utf-8', errors='replace'):
        """Unquote URLs into readable format.

        Should decoding failed , the method will try again replacing ``'%'`` with ``'\\x'`` then
        decoding the ``url`` as ``'unicode_escape'``.

        Args:
            url (str): URL string.

        Keyword Args:
            encoding (str): The encoding with which to decode the :obj:`bytes`.
            errors (str): The error handling scheme to use for the handling of decoding errors.
                The default is ``'strict'`` meaning that decoding errors raise a
                :exc:`UnicodeDecodeError`. Other possible values are ``'ignore'`` and ``'replace'``
                as well as any other name registered with :func:`codecs.register_error` that
                can handle :exc:`UnicodeDecodeError`.

        Returns:
            str: Unquoted string.

        See Also:
            :func:`urllib.parse.unquote`

        """
        try:
            return urllib.parse.unquote(url, encoding=encoding, errors=errors)
        except UnicodeError:
            return url.replace('%', r'\x').encode().decode('unicode_escape')

    @classmethod
    def id(cls):
        """Index ID of the protocol.

        By default, it returns the name of the protocol.

        Returns:
            Union[str, Tuple[str]]: Index ID of the protocol.

        See Also:
            :meth:`pcapkit.protocols.protocol.Protocol.__getitem__`

        """
        return cls.__name__

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, file=None, length=None, **kwargs):
        """Initialisation.

        Args:
            file (Optional[io.BytesIO]): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            _error (bool): If the object is initiated after parsing errors
                (:attr:`self._onerror <pcapkit.protocols.protocol.Protocol._onerror>`).
            _layer (str): Parse packet until ``_layer``
                (:attr:`self._onerror <pcapkit.protocols.protocol.Protocol._exlayer>`).
            _protocol (str): Parse packet until ``_protocol``
                (:attr:`self._onerror <pcapkit.protocols.protocol.Protocol._exproto>`).
            **kwargs: Arbitrary keyword arguments.

        """
        logger.debug(type(self).__name__)

        #: bool: If the object is initiated  after parsing errors.
        self._onerror = kwargs.pop('_error', False)
        #: str: Parse packet until such layer.
        self._exlayer = kwargs.pop('_layer', str())
        #: str: Parse packet until such protocol.
        self._exproto = kwargs.pop('_protocol', str())

        #: int: Initial offset of :attr:`self._file <pcapkit.protocols.protocol.Protocol._file>`
        self._seekset = (file or io.BytesIO()).tell()
        #: bool: If terminate parsing next layer of protocol.
        self._sigterm = self._check_term_threshold()

        # post-init customisations
        self.__post_init__(file, length, **kwargs)

    def __post_init__(self, file=None, length=None, **kwargs):
        """Post initialisation hook.

        Args:
            file (Optional[io.BytesIO]): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        if file is None:
            _data = self.make(**kwargs)
        else:
            _data = file.read(length)

        #: bytes: Raw packet data.
        self._data = _data
        #: io.BytesIO: Source packet stream.
        self._file = io.BytesIO(self._data)
        #: pcapkit.corekit.infoclass.Info: Parsed packet data.
        self._info = Info(self.read(length, **kwargs))

    def __repr__(self):
        """Returns representation of parsed protocol data.

        Example:
            >>> protocol
            <Frame Info(..., ethernet=Info(...), protocols='Ethernet:IPv6:Raw')>

        """
        repr_ = f"<{self.alias} {self._info!r}>"
        return repr_

    @cached_property
    def __str__(self):
        """Returns formatted hex representation of source data stream.

        Example:
            >>> protocol
            <Frame Info(..., packet=b"...", ethernet=Info(...), protocols='Ethernet:IPv6:Raw')>
            >>> print(protocol)
            00 00 00 00 00 00 00 a6 87 f9 27 93 16 ee fe 80 00 00 00     ..........'........
            00 00 00 1c cd 7c 77 ba c7 46 b7 87 00 0e aa 00 00 00 00     .....|w..F.........
            fe 80 00 00 00 00 00 00 1c cd 7c 77 ba c7 46 b7 01 01 a4     ..........|w..F....
            5e 60 d9 6b 97                                               ^`.k.

        """
        bytes_ = self._data

        hexbuf = ' '.join(textwrap.wrap(bytes_.hex(), 2))
        strbuf = ''.join(chr(char) if char in readable else '.' for char in bytes_)

        number = shutil.get_terminal_size().columns // 4 - 1
        length = number * 3

        hexlst = textwrap.wrap(hexbuf, length)
        strlst = list(iter(functools.partial(io.StringIO(strbuf).read, number), ''))

        str_ = os.linesep.join(map(lambda x: f'{x[0].ljust(length)}    {x[1]}', zip(hexlst, strlst)))  # pylint: disable=zip-builtin-not-iterating
        return str_

    def __bytes__(self):
        """Returns source data stream in :obj:`bytes`."""
        return self._data

    @cached_property
    def __len__(self):
        """Total length of corresponding protocol."""
        return len(self._data)

    def __length_hint__(self):
        """Return an estimated length for the object."""

    def __iter__(self):
        """Iterate through :attr:`self._data <pcapkit.protocols.protocol.Protocol._data>`."""
        return io.BytesIO(self._data)

    def __getitem__(self, key):
        """Subscription (``getitem``) support.

        * If ``key`` is a :obj`slice` object, :exc:`~pcapkit.utilities.exceptions.ProtocolUnbound`
          will be raised.
        * If ``key`` is a :class:`~pcapkit.protocols.protocol.Protocol` object,
          the method will fetch its indexes (:meth:`~pcapkit.protocols.protocol.Protocol.id`).
        * Later, search the packet's chain of protocols with the calculated ``key``.
        * If no matches, then raises :exc:`~pcapkit.utilities.exceptions.ProtocolNotFound`.

        Args:
            key (Union[str, Protocol, Type[Protocol]]): Indexing key.

        Returns:
            pcapkit.protocols.protocol.Protocol: The sub-packet from the current packet of indexed protocol.

        Raises:
            ProtocolUnbound: If ``key`` is a :obj:`slice` object.
            ProtocolNotFound: If ``key`` is not in the current packet.

        """
        # if key is a slice, raise ProtocolUnbound
        if isinstance(key, slice):
            raise ProtocolUnbound('protocol slice unbound')

        # if key is a protocol, then fetch protocol indexes
        try:
            flag = issubclass(key, Protocol)
        except TypeError:
            flag = issubclass(type(key), Protocol)
        if flag or isinstance(key, Protocol):
            key = key.id()

        # make regex for tuple indexes
        if isinstance(key, tuple):
            key = r'|'.join(map(re.escape, key))

        # if it's itself
        if re.fullmatch(key, self.__class__.__name__, re.IGNORECASE):
            return self

        # then check recursively
        from pcapkit.protocols.null import NoPayload  # pylint: disable=import-outside-toplevel

        payload = self._next
        while not isinstance(payload, NoPayload):
            if re.fullmatch(key, payload.__class__.__name__, re.IGNORECASE):
                return payload
            payload = payload.payload
        raise ProtocolNotFound(key)

    def __contains__(self, name):
        """Returns if ``name`` is in :attr:`self._info <pcapkit.protocols.protocol.Protocol._info>`.

        Args:
            name (Any): name to search

        Returns:
            bool: if ``name`` exists

        """
        return name in self._info

    @classmethod
    @abc.abstractmethod
    def __index__(cls):
        """Numeral registry index of the protocol.

        Returns:
            enum.IntEnum: Numeral registry index of the protocol.

        """

    @classmethod
    def __eq__(cls, other):
        """Returns if ``other`` is of the same protocol as the current object.

        Args:
            other (Union[Protocol, Type[Protocol]]): Comparision against the object.

        Returns:
            bool: If ``other`` is of the same protocol as the current object.

        """
        try:
            flag = issubclass(other, Protocol)
        except TypeError:
            flag = issubclass(type(other), Protocol)

        if isinstance(other, Protocol) or flag:
            return other.id() == cls.id()

        try:
            index = cls.id()
            if isinstance(index, tuple):
                return any(map(lambda x: re.fullmatch(other, x, re.IGNORECASE), index))
            return bool(re.fullmatch(other, index, re.IGNORECASE))
        except Exception:
            return False

    def __hash__(self):
        """Return the hash value for :attr:`self._data <pcapkit.protocols.protocol.Protocol._data>`."""
        return hash(self._data)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size):  # pylint: disable=no-self-use, unused-argument
        """Read next layer protocol type.

        Arguments:
            size (int): buffer size

        Returns:
            * If *succeed*, returns the name of next layer protocol (:obj:`str`).
            * If *fail*, returns ``None``.

        """

    def _read_fileng(self, *args, **kwargs):
        """Read file buffer (:attr:`self._file <pcapkit.protocols.protocol.Protocol._file>`).

        This method wraps the :meth:`file.read` call.

        Args:
            *args: arbitrary positional arguments

        Keyword Args:
            **kwargs: arbitrary keyword arguments

        Returns:
            bytes: Data read from file buffer.

        """
        return self._file.read(*args, **kwargs)

    def _read_unpack(self, size=1, *, signed=False, lilendian=False, quiet=False):
        """Read bytes and unpack for integers.

        Arguments:
            size (int): buffer size

        Keyword Arguments:
            signed (bool): signed flag
            lilendian (bool): little-endian flag
            quiet (bool): quiet (no exception) flag

        Returns:
            Optional[int]: unpacked data upon success

        Raises:
            StructError: If unpack (:func:`struct.pack`) failed, and :exc:`struct.error` raised.

        """
        endian = '<' if lilendian else '>'
        if size == 8:       # unpack to 8-byte integer (long long)
            kind = 'q' if signed else 'Q'
        elif size == 4:     # unpack to 4-byte integer (int / long)
            kind = 'i' if signed else 'I'
        elif size == 2:     # unpack to 2-byte integer (short)
            kind = 'h' if signed else 'H'
        elif size == 1:     # unpack to 1-byte integer (char)
            kind = 'b' if signed else 'B'
        else:               # do not unpack
            kind = None

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
                raise StructError(f'{self.__class__.__name__}: unpack failed')
        return buf

    def _read_binary(self, size=1):
        """Read bytes and convert into binaries.

        Arguments:
            size (int): buffer size

        Returns:
            str: binary bits (``0``/``1``)

        """
        bin_ = ''
        for _ in range(size):
            byte = self._file.read(1)
            bin_ += bin(ord(byte))[2:].zfill(8)
        return bin_

    @seekset
    def _read_packet(self, length=None, *, header=None, payload=None, discard=False):
        """Read raw packet data.

        Arguments:
            length (int): length of the packet

        Keyword Arguments:
            header (Optional[int]): length of the packet header
            payload (Optional[int]): length of the packet payload
            discard (bool): flag if discard header data

        Returns:
            * If ``header`` omits, returns the whole packet data in :obj:`bytes`.
            * If ``discard`` is set as ``True``, returns the packet body (in :obj:`bytes`) only.
            * Otherwise, returns the header and payload data as a :obj:`dict`::

                class Packet(TypedDict):
                    \"\"\"Header and payload data.\"\"\"

                    #: packet header
                    header: bytes
                    #: packet payload
                    payload: bytes

        """
        if header is not None:
            header = self._read_fileng(header)
            payload = self._read_fileng(payload)
            if discard:
                return payload
            return dict(header=header, payload=payload)
        return self._read_fileng(length)

    @classmethod
    def _make_pack(cls, integer, *, size=1, signed=False, lilendian=False):
        """Pack integers to bytes.

        Arguments:
            integer (int) integer to be packed

        Keyword arguments:
            size (int): buffer size
            signed (bool): signed flag
            lilendian (bool): little-endian flag

        Returns:
            bytes: Packed data upon success.

        Raises:
            StructError: If failed to pack the integer.

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
                fmt = f'{endian}{kind}'
                buf = struct.pack(fmt, integer)
            except struct.error:
                raise StructError(f'{cls.__name__}: pack failed') from None
        return buf

    @classmethod
    def _make_index(cls, name, default=None, *, namespace=None, reversed=False,  # pylint: disable=redefined-builtin
                    pack=False, size=4, signed=False, lilendian=False):
        """Return first index of ``name`` from a :obj:`dict` or enumeration.

        Arguments:
            name (Union[str, int, enum.IntEnum]): item to be indexed
            default (int): default value

        Keyword arguments:
            namespace (Union[dict, enum.EnumMeta]): namespace for item
            reversed (bool): if namespace is ``str -> int`` pairs
            pack (bool): if need :func:`struct.pack` to pack the result
            size (int): buffer size
            signed (bool): signed flag
            lilendian (bool): little-endian flag

        Returns:
            Union[int, bytes]: Index of ``name`` from a dict or enumeration.
            If ``packet`` is :data:`True`, returns :obj:`bytes`; otherwise,
            returns :obj:`int`.

        Raises:
            ProtocolNotImplemented: If ``name`` is **NOT** in ``namespace``
                and ``default`` is :data:`None`.

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
                    raise ProtocolNotImplemented(f'protocol {name!r} not implemented') from None
                index = default
        if pack:
            return cls._make_pack(index, size=size, signed=signed, lilendian=lilendian)
        return index

    def _decode_next_layer(self, dict_, proto=None, length=None):
        """Decode next layer protocol.

        Arguments:
            dict_ (dict): info buffer
            proto (int): next layer protocol index
            length (int): valid (*non-padding*) length

        Returns:
            dict: current protocol with next layer extracted

        """
        if self._onerror:
            next_ = beholder(self._import_next_layer)(self, proto, length)
        else:
            next_ = self._import_next_layer(proto, length)
        info, chain = next_.info, next_.protochain

        # make next layer protocol name
        layer = next_.alias.lower()
        # proto = next_.__class__.__name__

        # write info and protocol chain into dict
        dict_[layer] = info
        self._next = next_  # pylint: disable=attribute-defined-outside-init
        self._protos = ProtoChain(self.__class__, self.alias, basis=chain)  # pylint: disable=attribute-defined-outside-init
        return dict_

    def _import_next_layer(self, proto, length=None):  # pylint: disable=unused-argument
        """Import next layer extractor.

        Arguments:
            proto (int): next layer protocol index
            length (int): valid (*non-padding*) length

        Returns:
            pcapkit.protocols.protocol.Protocol: instance of next layer

        """
        if length is not None and length == 0:
            from pcapkit.protocols.null import NoPayload as protocol  # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.raw import Raw as protocol  # pylint: disable=import-outside-toplevel
        else:
            module, name = self.__proto__[proto]
            protocol = getattr(importlib.import_module(module), name)

        next_ = protocol(io.BytesIO(self._read_fileng(length)), length,
                         layer=self._exlayer, protocol=self._exproto)

        return next_

    def _check_term_threshold(self):
        """Check if reached termination threshold.

        Returns:
            bool: if reached termination threshold

        """
        index = self.id()
        layer = self.__layer__ or ''

        pattern = r'|'.join(index) if isinstance(index, tuple) else index
        iterable = self._exproto if isinstance(self._exproto, tuple) else (self._exproto,)

        layer_match = re.fullmatch(layer, self._exlayer, re.IGNORECASE)
        protocol_match = filter(lambda string: re.fullmatch(pattern, string, re.IGNORECASE), iterable)  # pylint: disable=filter-builtin-not-iterating

        return bool(list(protocol_match) or layer_match)
