# -*- coding: utf-8 -*-
"""Root Protocol
===================

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
import os
import shutil
import string
import struct
import textwrap
import urllib.parse
from typing import TYPE_CHECKING, Generic, TypeVar, cast, overload

import aenum
import chardet

from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.data.protocol import Packet as DataType_Packet
from pcapkit.utilities.compat import cached_property
from pcapkit.utilities.decorators import beholder, seekset
from pcapkit.utilities.exceptions import (ProtocolNotFound, ProtocolNotImplemented, StructError,
                                          UnsupportedCall)

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, BinaryIO, DefaultDict, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

__all__ = ['Protocol']

PT = TypeVar('PT', bound='Info')

# readable characters' order list
readable = [ord(char) for char in filter(lambda char: not char.isspace(), string.printable)]


class Protocol(Generic[PT], metaclass=abc.ABCMeta):
    """Abstract base class for all protocol family."""

    #: Parsed packet data.
    _info: 'PT'
    #: Raw packet data.
    _data: 'bytes'
    #: Source packet stream.
    _file: 'BinaryIO'
    #： Next layer protocol instance.
    _next: 'Protocol'
    #: Protocol chain instance.
    _protos: 'ProtoChain'

    # Internal data storage for cached properties.
    __cached__: 'dict[str, Any]'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol, can be one of ``Link``, ``Internet``, ``Transport``
    #: and ``Application``. For example, the layer of
    #: :class:`~pcapkit.protocols.link.Ethernet` is ``Link``. However, certain
    #: protocols are not in any layer, such as
    # :class:`~pcapkit.protocols.misc.raw.Raw`, and thus its layer is :obj:`None`.
    __layer__: 'Optional[Literal["Link", "Internet", "Transport", "Application"]]' = None

    #: Protocol index mapping for decoding next layer, c.f.
    # :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    #: The values should be a tuple representing the module name and class name.
    __proto__: 'DefaultDict[int, tuple[str, str]]' = collections.defaultdict(
        lambda: ('pcapkit.protocols.misc.raw', 'Raw'),
    )

    ##########################################################################
    # Properties.
    ##########################################################################

    # name of current protocol
    @property
    @abc.abstractmethod
    def name(self) -> 'str':
        """Name of current protocol."""

    # acronym of current protocol
    @property
    def alias(self) -> 'str':
        """Acronym of current protocol."""
        return self.__class__.__name__

    # key name for the info dict
    @property
    def info_name(self) -> 'str':
        """Key name of the :attr:`info` dict."""
        return self.__class__.__name__.lower()

    # info dict of current instance
    @property
    def info(self) -> 'PT':
        """Info dict of current instance."""
        return self._info

    # binary packet data if current instance
    @property
    def data(self) -> 'bytes':
        """Binary packet data of current instance."""
        return self._data

    # header length of current protocol
    @property
    @abc.abstractmethod
    def length(self) -> 'int':
        """Header length of current protocol."""

    # payload of current instance
    @property
    def payload(self) -> 'Protocol':
        """Payload of current instance."""
        return self._next

    # name of next layer protocol
    @property
    def protocol(self) -> 'Optional[str]':
        """Name of next layer protocol (if any)."""
        with contextlib.suppress(IndexError):
            return self._protos[0]
        return None

    # protocol chain of current instance
    @property
    def protochain(self) -> 'ProtoChain':
        """Protocol chain of current instance."""
        return self._protos

    # packet data
    @cached_property
    def packet(self) -> 'DataType_Packet':
        """DataType_Packet data of the protocol."""
        try:
            return self._read_packet(header=self.length)
        except UnsupportedCall:
            return DataType_Packet(
                header=b'',
                payload=self._read_packet(),
            )

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[str, ...]':
        """Index ID of the protocol.

        By default, it returns the name of the protocol. In certain cases, the
        method may return multiple values.

        See Also:
            :meth:`pcapkit.protocols.protocol.Protocol.__getitem__`

        """
        return (cls.__name__,)

    @abc.abstractmethod
    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'PT':
        """Read (parse) packet data.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """

    @abc.abstractmethod
    def make(self, **kwargs: 'Any') -> 'bytes':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """

    @staticmethod
    def decode(byte: bytes, *, encoding: 'Optional[str]' = None,
               errors: 'Literal["strict", "ignore", "replace"]' = 'strict') -> 'str':
        """Decode :obj:`bytes` into :obj:`str`.

        Should decoding failed using ``encoding``, the method will try again decoding
        the :obj:`bytes` as ``'unicode_escape'`` with ``'replace'`` for error handling.

        See Also:
            The method is a wrapping function for :meth:`bytes.decode`.

        Args:
            byte: Source bytestring.
            encoding: The encoding with which to decode the :obj:`bytes`.
                If not provided, :mod:`pcapkit` will first try detecting its encoding
                using |chardet|_. The fallback encoding would is **UTF-8**.
            errors: The error handling scheme to use for the handling of decoding errors.
                The default is ``'strict'`` meaning that decoding errors raise a
                :exc:`UnicodeDecodeError`. Other possible values are ``'ignore'`` and ``'replace'``
                as well as any other name registered with :func:`codecs.register_error` that
                can handle :exc:`UnicodeDecodeError`.

        .. |chardet| replace:: ``chardet``
        .. _chardet: https://chardet.readthedocs.io

        """
        charset = encoding or chardet.detect(byte)['encoding'] or 'utf-8'
        try:
            return byte.decode(charset, errors=errors)
        except UnicodeError:
            return byte.decode('unicode_escape', errors='replace')

    @staticmethod
    def unquote(url: str, *, encoding : 'str' = 'utf-8',
                errors: 'Literal["strict", "ignore", "replace"]' = 'replace') -> 'str':
        """Unquote URLs into readable format.

        Should decoding failed , the method will try again replacing ``'%'`` with ``'\\x'`` then
        decoding the ``url`` as ``'unicode_escape'`` with ``'replace'`` for error handling.

        See Also:
            This method is a wrapper function for :func:`urllib.parse.unquote`.

        Args:
            url: URL string.
            encoding: The encoding with which to decode the :obj:`bytes`.
            errors: The error handling scheme to use for the handling of decoding errors.
                The default is ``'strict'`` meaning that decoding errors raise a
                :exc:`UnicodeDecodeError`. Other possible values are ``'ignore'`` and ``'replace'``
                as well as any other name registered with :func:`codecs.register_error` that
                can handle :exc:`UnicodeDecodeError`.

        """
        try:
            return urllib.parse.unquote(url, encoding=encoding, errors=errors)
        except UnicodeError:
            return url.replace('%', r'\x').encode().decode('unicode_escape', errors='replace')

    @staticmethod
    def expand_comp(value: 'str | Protocol | Type[Protocol]') -> 'tuple':
        """Expand protocol class to protocol name.

        The method is used to expand protocol class to protocol name, in the
        following manner:

        1. If ``value`` is a protocol instance, the method will return the
           protocol class, and the protocol names in upper case obtained from
           :meth:`Protocol.id <pcapkit.protocols.protocol.Protocol.id>`.
        2. If ``value`` is a protocol class, the method will return the
           protocol class itself, and the protocols names in upper case
           obtained from :meth:`Protocol.id <pcapkit.protocols.protocol.Protocol.id>`.
        3. If ``value`` is :obj:`str`, the method will attempt to search for
           the existing registered protocol class from
           :data:`pcapkit.protocols.__proto__` and follow **step 2**; otherwise,
           return the value itself.

        Args:
            value: Protocol class or name.

        """
        if isinstance(value, type) and issubclass(value, Protocol):
            comp = (value, *(name.upper() for name in value.id()))
        elif isinstance(value, Protocol):
            comp = (type(value), *(name.upper() for name in value.id()))
        else:
            from pcapkit.protocols import __proto__ as protocols_registry  # pylint: disable=import-outside-toplevel # isort: skip

            if (proto := protocols_registry.get(value.upper())) is not None:
                comp = (proto, *(name.upper() for name in proto.id()))
            else:
                comp = (value.upper(),)
        return comp

    @classmethod
    def analyze(cls, proto: 'int', payload: 'bytes', **kwargs: 'Any') -> 'Protocol':
        """Analyse packet payload.

        Args:
            proto: Protocol registry number.
            payload: Packet payload.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed payload as a :class:`~pcapkit.protocols.protocol.Protocol`
            instance.

        """
        module, name = cls.__proto__[proto]
        protocol = cast('Type[Protocol]', getattr(importlib.import_module(module), name))

        payload_io = io.BytesIO(payload)
        try:
            report = protocol(payload_io, len(payload), **kwargs)  # type: ignore[abstract]
        except Exception as exc:
            if isinstance(exc, StructError) and exc.eof:  # pylint: disable=no-member
                from pcapkit.protocols.misc.null import NoPayload as protocol  # type: ignore[no-redef] # pylint: disable=import-outside-toplevel # isort: skip
            else:
                from pcapkit.protocols.misc.raw import Raw as protocol  # type: ignore[no-redef] # pylint: disable=import-outside-toplevel # isort: skip
            # error = traceback.format_exc(limit=1).strip().rsplit(os.linesep, maxsplit=1)[-1]

            # log error
            #logger.error(str(exc), exc_info=exc, stack_info=DEVMODE, stacklevel=stacklevel())

            report = protocol(payload_io, len(payload), **kwargs)  # type: ignore[abstract]
        return report

    ##########################################################################
    # Data models.
    ##########################################################################

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'Protocol[PT]':  # pylint: disable=unused-argument
        self = super().__new__(cls)

        # NOTE: Assign this attribute after ``__new__`` to avoid shared memory
        # reference between instances.
        self.__cached__ = {}

        return self

    @overload
    def __init__(self, file: 'BinaryIO', length: 'Optional[int]' = ..., **kwargs: 'Any') -> 'None': ...
    @overload
    def __init__(self, **kwargs: 'Any') -> 'None': ...

    def __init__(self, file: 'Optional[BinaryIO]' = None, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'None':
        """Initialisation.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            _layer (str): Parse packet until ``_layer``
                (:attr:`self._exlayer <pcapkit.protocols.protocol.Protocol._exlayer>`).
            _protocol (str | Protocol | Type[Protocol]): Parse packet until ``_protocol``
                (:attr:`self._exproto <pcapkit.protocols.protocol.Protocol._exproto>`).
            **kwargs: Arbitrary keyword arguments.

        """
        #logger.debug('%s(file, %s, **%s)', type(self).__name__, length, kwargs)

        #: int: File pointer.
        self._seekset = io.SEEK_SET  # type: int
        #: str: Parse packet until such layer.
        self._exlayer = kwargs.pop('_layer', None)  # type: Optional[str]
        #: str: Parse packet until such protocol.
        self._exproto = kwargs.pop('_protocol', None)  # type: Optional[str | Protocol | Type[Protocol]]
        #: bool: If terminate parsing next layer of protocol.
        self._sigterm = self._check_term_threshold()

        # post-init customisations
        self.__post_init__(file, length, **kwargs)  # type: ignore[arg-type]

    @overload
    def __post_init__(self, file: 'BinaryIO', length: 'Optional[int]' = ..., **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...

    def __post_init__(self, file: 'Optional[BinaryIO]' = None,
                      length: 'Optional[int]' = None, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction arguments, please refer to
            :meth:`self.make <pcapkit.protocols.protocol.Protocol.make>`.

        """
        if file is None:
            _data = self.make(**kwargs)
        else:
            _data = file.read(length)  # type: ignore[arg-type]

        #: bytes: Raw packet data.
        self._data = _data
        #: io.BytesIO: Source packet stream.
        self._file = io.BytesIO(self._data)
        #: pcapkit.corekit.infoclass.Info: Parsed packet data.
        self._info = self.read(length, **kwargs)

    def __repr__(self) -> 'str':
        """Returns representation of parsed protocol data.

        Example:
            >>> protocol
            <Frame alias='...' frame=(..., packet=b'...', sethernet=..., protocols='Ethernet:IPv6:Raw')>

        """
        if (cached := self.__cached__.get('__repr__')) is not None:
            return cached

        name = type(self).__name__
        temp = []  # type: list[str]
        for (key, value) in self._info.items():
            if isinstance(value, Info):
                temp.append(f'{key}=...')
            else:
                temp.append(f'{key}={value!r}')
        args = ', '.join(temp)

        # cache and return
        repr_ = f'<{name} alias={self.alias!r} {self.info_name}=({args})>'

        self.__cached__['__repr__'] = repr_
        return repr_

    def __str__(self) -> 'str':
        """Returns formatted hex representation of source data stream.

        Example:
            >>> protocol
            Frame(..., packet=b"...", sethernet=..., protocols='Ethernet:IPv6:Raw')
            >>> print(protocol)
            00 00 00 00 00 00 00 a6 87 f9 27 93 16 ee fe 80 00 00 00     ..........'........
            00 00 00 1c cd 7c 77 ba c7 46 b7 87 00 0e aa 00 00 00 00     .....|w..F.........
            fe 80 00 00 00 00 00 00 1c cd 7c 77 ba c7 46 b7 01 01 a4     ..........|w..F....
            5e 60 d9 6b 97                                               ^`.k.

        """
        if (cached := self.__cached__.get('__str__')) is not None:
            return cached

        hexbuf = ' '.join(textwrap.wrap(self._data.hex(), 2))
        strbuf = ''.join(chr(char) if char in readable else '.' for char in self._data)

        number = shutil.get_terminal_size().columns // 4 - 1
        length = number * 3

        hexlst = textwrap.wrap(hexbuf, length)
        strlst = list(iter(functools.partial(io.StringIO(strbuf).read, number), ''))

        # cache and return
        str_ = os.linesep.join(map(lambda x: f'{x[0].ljust(length)}    {x[1]}', zip(hexlst, strlst)))

        self.__cached__['__str__'] = str_
        return str_

    def __bytes__(self) -> 'bytes':
        """Returns source data stream in :obj:`bytes`."""
        return self._data

    def __len__(self) -> 'int':
        """Total length of corresponding protocol."""
        if (cached := self.__cached__.get('__len__')) is not None:
            return cached

        # cache and return
        len_ = len(self._data)

        self.__cached__['__len__'] = len_
        return len_

    def __length_hint__(self) -> 'Optional[int]':
        """Return an estimated length for the object."""

    def __iter__(self) -> 'BinaryIO':
        """Iterate through :attr:`self._data <pcapkit.protocols.protocol.Protocol._data>`."""
        return io.BytesIO(self._data)

    def __getitem__(self, key: 'str | Protocol | Type[Protocol]') -> 'Protocol':
        """Subscription (``getitem``) support.

        * If ``key`` is a :class:`~pcapkit.protocols.protocol.Protocol` object,
          the method will fetch its indexes (:meth:`~pcapkit.protocols.protocol.Protocol.id`).
        * Later, search the packet's chain of protocols with the calculated ``key``.
        * If no matches, then raises :exc:`~pcapkit.utilities.exceptions.ProtocolNotFound`.

        Args:
            key: Indexing key.

        Returns:
            The sub-packet from the current packet of indexed protocol.

        Raises:
            ProtocolNotFound: If ``key`` is not in the current packet.

        See Also:
            The method calls
            :meth:`self.expand_comp <pcapkit.protocols.protocol.Protocol.expand_comp>`
            to handle the ``key`` and expand it for robust searching.

        """
        comp = self.expand_comp(key)

        # if it's itself
        test_comp = (type(self), *(name.upper() for name in self.id()))
        for test in comp:
            if test in test_comp:
                return self

        # then check recursively
        from pcapkit.protocols.misc.null import NoPayload  # pylint: disable=import-outside-toplevel

        payload = self._next
        while not isinstance(payload, NoPayload):
            test_comp = (type(payload), *(name.upper() for name in payload.id()))
            for test in comp:
                if test in test_comp:
                    return payload
            payload = payload.payload
        raise ProtocolNotFound(key)

    def __contains__(self, name: 'str | Protocol | Type[Protocol]') -> 'bool':
        """Returns if certain protocol is in the instance.

        Args:
            name: Name to search

        See Also:
            The method calls
            :meth:`self.expand_comp <pcapkit.protocols.protocol.Protocol.expand_comp>`
            to handle the ``name`` and expand it for robust searching.

        """
        comp = self.expand_comp(name)

        # if it's itself
        test_comp = (type(self), *(name.upper() for name in self.id()))
        for test in comp:
            if test in test_comp:
                return True

        # then check recursively
        from pcapkit.protocols.misc.null import NoPayload  # pylint: disable=import-outside-toplevel

        payload = self._next
        while not isinstance(payload, NoPayload):
            test_comp = (type(payload), *(name.upper() for name in payload.id()))
            for test in comp:
                if test in test_comp:
                    return True
            payload = payload.payload
        return False

    @classmethod
    @abc.abstractmethod
    def __index__(cls) -> 'StdlibEnum | AenumEnum':
        """Numeral registry index of the protocol."""

    @classmethod
    def __eq__(cls, other: 'object') -> 'bool':
        """Returns if ``other`` is of the same protocol as the current object.

        Args:
            other: Comparision against the object.

        """
        if isinstance(other, type) and issubclass(other, Protocol):
            return cls is other
        if isinstance(other, Protocol):
            return cls.id() == other.id()

        if isinstance(other, str):
            test_comp = cls.expand_comp(cls)
            return other.upper() in test_comp
        return False

    def __hash__(self) -> 'int':
        """Return the hash value for :attr:`self._data <pcapkit.protocols.protocol.Protocol._data>`."""
        return hash(self._data)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size: int) -> 'Optional[StdlibEnum | AenumEnum]':  # pylint: disable=unused-argument
        """Read next layer protocol type.

        * If *succeed*, returns the enum of next layer protocol.
        * If *fail*, returns :obj:`None`.

        Arguments:
            size: buffer size

        """

    def _read_fileng(self, *args: 'Any', **kwargs: 'Any') -> 'bytes':
        """Read file buffer (:attr:`self._file <pcapkit.protocols.protocol.Protocol._file>`).

        This method wraps the :meth:`file.read <io.BytesIO.read>` call.

        Args:
            *args: arbitrary positional arguments
            **kwargs: arbitrary keyword arguments

        Returns:
            bytes: Data read from file buffer.

        """
        return self._file.read(*args, **kwargs)

    def _read_unpack(self, size: 'int' = 1, *, signed: 'bool' = False,
                     lilendian: 'bool' = False, quiet: 'bool' = False) -> 'int':
        """Read bytes and unpack for integers.

        Arguments:
            size: buffer size
            signed: signed flag
            lilendian: little-endian flag
            quiet: quiet (no exception) flag

        Returns:
            Unpacked data upon success

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

        mem = self._file.read(size)
        if not mem:
            raise StructError('unpack: empty buffer', quiet=True, eof=True)

        if kind is None:
            end = 'little' if lilendian else 'big'  # type: Literal['little', 'big']
            buf = int.from_bytes(mem, end, signed=signed)
        else:
            fmt = f'{endian}{kind}'
            try:
                buf = struct.unpack(fmt, mem)[0]  # pylint: disable=no-member
            except struct.error as error:  # pylint: disable=no-member
                if quiet:
                    end = 'little' if lilendian else 'big'
                    buf = int.from_bytes(mem, end, signed=signed)
                    return buf
                raise StructError(f'{self.__class__.__name__}: unpack failed') from error
        return buf

    def _read_binary(self, size: 'int' = 1) -> 'str':
        """Read bytes and convert into binaries.

        Arguments:
            size: buffer size

        Returns:
            Binary bits (``0``/``1``).

        """
        bin_ = []  # type: list[str]
        for _ in range(size):
            byte = self._file.read(1)
            bin_.append(bin(ord(byte))[2:].zfill(8))
        return ''.join(bin_)

    @overload
    def _read_packet(self, length: 'Optional[int]' = ..., *, header: 'None' = ...) -> 'bytes': ...
    @overload
    def _read_packet(self, *, header: 'int', payload: 'Optional[int]' = ..., discard: 'Literal[True]') -> 'bytes': ...
    @overload
    def _read_packet(self, *, header: 'int', payload: 'Optional[int]' = ..., discard: 'Literal[False]' = ...) -> 'DataType_Packet': ...  # pylint: disable=line-too-long

    @seekset  # type: ignore[misc]
    def _read_packet(self, length: 'Optional[int]' = None, *, header: 'Optional[int]' = None,
                     payload: 'Optional[int]' = None, discard: bool = False) -> 'bytes | DataType_Packet':
        """Read raw packet data.

        Arguments:
            length: length of the packet
            header: length of the packet header
            payload: length of the packet payload
            discard: flag if discard header data

        * If ``header`` omits, returns the whole packet data in :obj:`bytes`.
        * If ``discard`` is set as :data:`True`, returns the packet body (in
          :obj:`bytes`) only.
        * Otherwise, returns the header and payload data as
          :class:`~pcapkit.protocols.data.protocol.DataType_Packet` object.

        """
        if header is not None:
            data_header = self._read_fileng(header)
            data_payload = self._read_fileng(payload)
            if discard:
                return data_payload
            return DataType_Packet(
                header=data_header,
                payload=data_payload
            )
        return self._read_fileng(length)

    @classmethod
    def _make_pack(cls, integer: 'int', *, size: 'int' = 1,
                   signed: 'bool' = False, lilendian: 'bool' = False) -> 'bytes':
        """Pack integers to bytes.

        Arguments:
            integer: integer to be packed
            size: buffer size
            signed: signed flag
            lilendian: little-endian flag

        Returns:
            Packed data upon success.

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
            end = 'little' if lilendian else 'big'  # type: Literal['little', 'big']
            buf = integer.to_bytes(size, end, signed=signed)
        else:
            try:
                fmt = f'{endian}{kind}'
                buf = struct.pack(fmt, integer)  # pylint: disable=no-member
            except struct.error as error:  # pylint: disable=no-member
                raise StructError(f'{cls.__name__}: pack failed') from error
        return buf

    @overload
    @classmethod
    def _make_index(cls, name: 'int | StdlibEnum | AenumEnum', *, pack: 'Literal[False]' = ...) -> 'int': ...
    @overload
    @classmethod
    def _make_index(cls, name: 'int | StdlibEnum | AenumEnum', *, pack: 'Literal[True]',
                    size: 'int' = ..., signed: 'bool' = ..., lilendian: 'bool' = ...) -> 'bytes': ...
    @overload
    @classmethod
    def _make_index(cls, name: 'str', default: 'Optional[int]' = ..., *,
                    namespace: 'Type[StdlibEnum] | Type[AenumEnum]', pack: 'Literal[False]' = ...) -> 'int': ...
    @overload
    @classmethod
    def _make_index(cls, name: 'str', default: 'Optional[int]' = ..., *,
                    namespace: 'Type[StdlibEnum] | Type[AenumEnum]', pack: 'Literal[True]',
                    size: 'int' = ..., signed: 'bool' = ..., lilendian: 'bool' = ...) -> 'bytes': ...
    @overload
    @classmethod
    def _make_index(cls, name: 'str', default: 'Optional[int]' = ..., *, namespace: 'dict[int, str]',
                    reversed: 'Literal[False]' = ...,  # pylint: disable=redefined-builtin
                    pack: 'Literal[False]' = ...) -> 'int': ...
    @overload
    @classmethod
    def _make_index(cls, name: 'str', default: 'Optional[int]' = ..., *, namespace: 'dict[int, str]',
                    reversed: 'Literal[False]' = ...,  # pylint: disable=redefined-builtin
                    pack: 'Literal[True]', size: 'int' = ..., signed: 'bool' = ...,
                    lilendian: 'bool' = ...) -> 'bytes': ...
    @overload
    @classmethod
    def _make_index(cls, name: 'str', default: 'Optional[int]' = ..., *, namespace: 'dict[str, int]',
                    reversed: 'Literal[True]',  # pylint: disable=redefined-builtin
                    pack: 'Literal[False]' = ...) -> 'int': ...
    @overload
    @classmethod
    def _make_index(cls, name: 'str', default: 'Optional[int]' = ..., *, namespace: 'dict[str, int]',
                    reversed: 'Literal[True]',  # pylint: disable=redefined-builtin
                    pack: 'Literal[True]', size: 'int' = ..., signed: 'bool' = ...,
                    lilendian: 'bool' = ...) -> 'bytes': ...

    @classmethod
    def _make_index(cls, name: 'str | int | StdlibEnum | AenumEnum', default: 'Optional[int]' = None, *,
                    namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,
                    reversed: 'bool' = False,  # pylint: disable=redefined-builtin
                    pack: 'bool' = False, size: 'int' = 4, signed: 'bool' = False,
                    lilendian: 'bool' = False) -> 'int | bytes':
        """Return first index of ``name`` from a :obj:`dict` or enumeration.

        Arguments:
            name: item to be indexed
            default: default value
            namespace: namespace for item
            reversed: if namespace is ``str -> int`` pairs
            pack: if need :func:`struct.pack` to pack the result
            size: buffer size
            signed: signed flag
            lilendian: little-endian flag

        Returns:
            Index of ``name`` from a dict or enumeration. If ``pack`` is
            :data:`True`, returns :obj:`bytes`; otherwise, returns :obj:`int`.

        Raises:
            ProtocolNotImplemented: If ``name`` is **NOT** in ``namespace``
                and ``default`` is :data:`None`.

        """
        if isinstance(name, (enum.IntEnum, aenum.IntEnum)):
            index = cast('int', name.value)
        elif isinstance(name, int):
            index = name
        else:  # name is str
            try:
                if isinstance(namespace, type) and issubclass(namespace, (enum.IntEnum, aenum.IntEnum)):
                    index = cast('int', namespace[name].value)
                elif isinstance(namespace, dict):
                    if reversed:
                        if TYPE_CHECKING:
                            namespace = cast('dict[str, int]', namespace)
                        index = namespace[name]
                    else:
                        if TYPE_CHECKING:
                            namespace = cast('dict[int, str]', namespace)
                        index = {v: k for k, v in namespace.items()}[name]
                else:
                    raise KeyError(name)
            except KeyError as error:
                if default is None:
                    raise ProtocolNotImplemented(f'protocol {name!r} not implemented') from error
                index = default

        if pack:
            return cls._make_pack(index, size=size, signed=signed, lilendian=lilendian)
        return index

    def _decode_next_layer(self, dict_: 'PT', proto: 'int', length: 'Optional[int]' = None) -> 'PT':
        r"""Decode next layer protocol.

        Arguments:
            dict\_: info buffer
            proto: next layer protocol index
            length: valid (*non-padding*) length

        Returns:
            Current protocol with next layer extracted.

        """
        next_ = self._import_next_layer(proto, length)  # type: ignore[call-arg,misc]
        info, chain = next_.info, next_.protochain

        # make next layer protocol name
        layer = next_.info_name
        # proto = next_.__class__.__name__

        # write info and protocol chain into dict
        dict_.__update__([(layer, info)])
        self._next = next_  # pylint: disable=attribute-defined-outside-init
        self._protos = ProtoChain(self.__class__, self.alias, basis=chain)  # pylint: disable=attribute-defined-outside-init
        return dict_

    @beholder
    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None) -> 'Protocol':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index
            length: valid (*non-padding*) length

        Returns:
            Instance of next layer.

        """
        if TYPE_CHECKING:
            protocol: 'Type[Protocol]'

        if length is not None and length == 0:
            from pcapkit.protocols.misc.null import NoPayload as protocol  # type: ignore[no-redef] # isort: skip # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.misc.raw import Raw as protocol  # type: ignore[no-redef] # isort: skip # pylint: disable=import-outside-toplevel
        else:
            module, name = self.__proto__[proto]
            protocol = cast('Type[Protocol]', getattr(importlib.import_module(module), name))

        next_ = protocol(self._file, length, alias=proto,
                         layer=self._exlayer, protocol=self._exproto)  # type: ignore[abstract]
        return next_

    def _check_term_threshold(self) -> bool:
        """Check if reached termination threshold."""
        if self._exlayer is None or (layer := self.__layer__) is None:
            layer_match = False
        else:
            layer_match = layer.upper() == self._exlayer.upper()

        if self._exproto is None:
            protocol_match = False
        else:
            protocol_match = False
            comp_test = [name.upper() for name in self.id()]
            for test in self.expand_comp(self._exproto):
                if test in comp_test:
                    protocol_match = True
                    break

        return layer_match or protocol_match
