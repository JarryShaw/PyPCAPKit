# -*- coding: utf-8 -*-
"""root protocol

:mod:`pcapkit.protocols.protocol` contains
:class:`~pcapkit.protocols.protocol.Protocol` only, which is
an abstract base class for all protocol family, with pre-defined
utility arguments and methods of specified protocols.

"""
import abc
import collections
import copy
import functools
import importlib
import io
import os
import re
import shutil
import string
import struct
import textwrap
import urllib

import chardet

from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.utilities.decorators import beholder, seekset
from pcapkit.utilities.exceptions import ProtocolNotFound, ProtocolUnbound, StructError

__all__ = ['Protocol']

# readable characters' order list
readable = [ord(char) for char in filter(lambda char: not char.isspace(), string.printable)]


@functools.total_ordering
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
        try:
            return self._protos[1]
        except IndexError:
            return None

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

    @staticmethod
    def decode(byte, *, encoding=None, errors='strict'):
        """Decode :obj:`bytes` into :obj:`str`.

        Args:
            byte (bytes): Source bytestring.

        Keyword Args:
            encoding (Optional[str]): The encoding with which to decode the :obj:`bytes`.
                If not provided, :mod:`pcapkit` will first try detecting its encoding
                using |chardet|_. The fallback encoding would is **UTF-8**.
            errors (str): The error handling scheme to use for the handling of decoding errors.
                The default is ``'strict'`` meaning that decoding errors raise a
                ``UnicodeDecodeError``. Other possible values are ``'ignore'`` and ``'replace'``
                as well as any other name registered with :func:`codecs.register_error` that
                can handle ``UnicodeDecodeError``.

        Returns:
            str: Decoede string.

        Should decoding failed using ``encoding``, the method will try again decoding
        the :obj:`bytes` as ``'unicode_escape'``.

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

        Args:
            url (str): URL string.

        Keyword Args:
            encoding (str): The encoding with which to decode the :obj:`bytes`.
            errors (str): The error handling scheme to use for the handling of decoding errors.
                The default is ``'strict'`` meaning that decoding errors raise a
                ``UnicodeDecodeError``. Other possible values are ``'ignore'`` and ``'replace'``
                as well as any other name registered with :func:`codecs.register_error` that
                can handle ``UnicodeDecodeError``.

        Returns:
            str: Unquoted string.

        Should decoding failed , the method will try again replacing ``'%'`` with ``'\\x'`` then
        decoding the ``url`` as ``'unicode_escape'``.

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

    def __new__(cls, file=None, *args, **kwargs):  # pylint: disable=keyword-arg-before-vararg,unused-argument
        """Create and return a new object.

        Args:
            file (io.BytesIO): Source packet stream.
            *args: Arbitrary positional arguments.

        Keyword Args:
            error (bool): If the object is initiated after parsing errors
                (:attr:`self._onerror <pcapkit.protocols.protocol.Protocol._onerror>`).
            layer (str): Parse packet until ``layer``
                (:attr:`self._onerror <pcapkit.protocols.protocol.Protocol._exlayer>`).
            protocol (str): Parse packet until ``protocol``
                (:attr:`self._onerror <pcapkit.protocols.protocol.Protocol._exproto>`).
            **kwargs: Arbitrary keyword arguments.

        Returns:
            pcapkit.protocols.protocol.Protocol: The new object.

        """
        self = super().__new__(cls)

        #: bool: If the object is initiated  after parsing errors.
        self._onerror = kwargs.pop('error', False)
        #: str: Parse packet until such layer.
        self._exlayer = kwargs.pop('layer', str())
        #: str: Parse packet until such protocol.
        self._exproto = kwargs.pop('protocol', str())

        #: int: Initial offset of :attr:`self._file <pcapkit.protocols.protocol.Protocol._file>`
        self._seekset = (file or io.BytesIO()).tell()
        #: bool: If terminate parsing next layer of protocol.
        self._sigterm = self._check_term_threshold()

        return self

    @abc.abstractmethod
    def __init__(self, file=None, *args, **kwargs):  # pylint: disable=keyword-arg-before-vararg,unused-argument
        """Initialisation.

        Args:
            file (io.BytesIO): Source packet stream.
            *args: Arbitrary positional arguments.

        Keyword Args:
            error (bool): If the object is initiated after parsing errors
                (:attr:`self._onerror <pcapkit.protocols.protocol.Protocol._onerror>`).
            layer (str): Parse packet until ``layer``
                (:attr:`self._onerror <pcapkit.protocols.protocol.Protocol._exlayer>`).
            protocol (str): Parse packet until ``protocol``
                (:attr:`self._onerror <pcapkit.protocols.protocol.Protocol._exproto>`).
            **kwargs: Arbitrary keyword arguments.

        """
        #: bool: If the object is initiated  after parsing errors.
        self._onerror = kwargs.pop('error', False)
        #: str: Parse packet until such layer.
        self._exlayer = kwargs.pop('layer', str())
        #: str: Parse packet until such protocol.
        self._exproto = kwargs.pop('protocol', str())

        #: int: Initial offset of :attr:`self._file <pcapkit.protocols.protocol.Protocol._file>`
        self._seekset = (file or io.BytesIO()).tell()
        #: bool: If terminate parsing next layer of protocol.s
        self._sigterm = self._check_term_threshold()

        #: io.BytesIO: Source packet stream.
        self._file = file
        #: pcapkit.corekit.infoclass.Info: Parsed packet data.
        self._info = Info()

    def __repr__(self):
        """Returns representation of parsed protocol data.

        Example:
            >>> protocol
            <Frame Info(..., ethernet=Info(...), protocols='Ethernet:IPv6:Raw')>

        """
        repr_ = f"<{self.alias} {self._info!r}>"
        return repr_

    @seekset
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
        bytes_ = self._read_fileng()

        hexbuf = ' '.join(textwrap.wrap(bytes_.hex(), 2))
        strbuf = ''.join(chr(char) if char in readable else '.' for char in bytes_)

        number = shutil.get_terminal_size().columns // 4 - 1
        length = number * 3

        hexlst = textwrap.wrap(hexbuf, length)
        strlst = list(iter(functools.partial(io.StringIO(strbuf).read, number), ''))

        str_ = os.linesep.join(map(lambda x: f'{x[0].ljust(length)}    {x[1]}', zip(hexlst, strlst)))  # pylint: disable=zip-builtin-not-iterating
        return str_

    @seekset
    def __bytes__(self):
        """Returns source data stream in :obj:`bytes`."""
        bytes_ = self._read_fileng()
        return bytes_

    @seekset
    def __len__(self):
        """Total length of corresponding protocol."""
        return len(self._read_fileng())

    def __length_hint__(self):
        """Return an estimated length for the object."""

    def __iter__(self):
        """Iterate through :attr:`self._file <pcapkit.protocols.protocol.Protocol>`."""
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
        """Subscription (``getitem``) support.

        * If ``key`` is a ``slice`` object, :exc:`ProtocolUnbound` will be
          raised.
        * If ``key`` is a :class`~pcapkit.protocols.protocol.Protocol` object,
          the method will fetch its indexes (:meth`~pcapkit.protocols.protocol.Protocol.id`).
        * Later, search the packet's chain of protocols with the calculated
          ``key``.
        * If no matches, then raises :exc:`ProtocolNotFound`.

        Args:
            key (Union[str, Protocol, Type[Protocol]]): Indexing key.

        Returns:
            pcapkit.protocols.protocol.Protocol: The sub-packet from the current packet of indexed protocol.

        Raises:
            ProtocolUnbound: If ``key`` is a ``slice`` object.
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
        raise ProtocolNotFound(f"Layer {key!r} not in Frame")

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

    @classmethod
    def __lt__(cls, other):
        """Rich comparison is not supported."""
        return NotImplemented
        # raise ComparisonError(f"Rich comparison not supported between instances of 'Protocol' "
        #                       f"and {type(other).__name__!r}")

    def __hash__(self):
        """Return the hash value for :attr:`self._info <pcapkit.protocols.protocol.Protocol._info>`."""
        return hash(self._info)

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
        return None

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
            header (int): length of the packet header
            payload (int): length of the packet payload
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
            payload = self._read_fileng(*[payload])
            if discard:
                return payload
            return dict(header=header, payload=payload)
        return self._read_fileng(*[length])

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
