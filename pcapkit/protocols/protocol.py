# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""Root Protocol
===================

.. module:: pcapkit.protocols.protocol

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
import io
import os
import shutil
import string
import struct
import textwrap
import urllib.parse
from typing import TYPE_CHECKING, Any, Generic, Optional, Type, TypeVar, cast, overload

import aenum
import chardet

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols import data as data_module
from pcapkit.protocols import schema as schema_module
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.misc.raw import Raw as Data_Raw
from pcapkit.protocols.data.protocol import Packet as Data_Packet
from pcapkit.protocols.schema.misc.raw import Raw as Schema_Raw
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.compat import cached_property
from pcapkit.utilities.decorators import beholder, seekset
from pcapkit.utilities.exceptions import (ProtocolNotFound, ProtocolNotImplemented, RegistryError,
                                          StructError, UnsupportedCall)
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import IO, Any, DefaultDict, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal, Self

__all__ = ['ProtocolBase']

_PT = TypeVar('_PT', bound='Data')
_ST = TypeVar('_ST', bound='Schema')

# readable characters' order list
readable = [ord(char) for char in filter(lambda char: not char.isspace(), string.printable)]


class ProtocolMeta(abc.ABCMeta):
    """Meta class to add dynamic support to :class:`Protocol`.

    This meta class is used to generate necessary attributes for the
    :class:`Protocol` class. It can be useful to reduce unnecessary
    registry calls and simplify the customisation process.

    """


class ProtocolBase(Generic[_PT, _ST], metaclass=ProtocolMeta):
    """Abstract base class for all protocol family.

    Note:
        This class is for internal use only. For customisation, please use
        :class:`Protocol` instead.

    """

    if TYPE_CHECKING:
        #: Parsed packet data.
        _info: '_PT'
        #: Raw packet data.
        _data: 'bytes'
        #: Source packet stream.
        _file: 'IO[bytes]'
        #: Next layer protocol instance.
        _next: 'ProtocolBase'
        #: Protocol chain instance.
        _protos: 'ProtoChain'

        # Internal data storage for cached properties.
        __cached__: 'dict[str, Any]'
        #: Protocol packet data definition.
        __data__: 'Type[_PT]'
        #: Protocol header schema definition.
        __schema__: 'Type[_ST]'
        #: Protocol header schema instance.
        __header__: '_ST'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol, can be one of ``Link``, ``Internet``, ``Transport``
    #: and ``Application``. For example, the layer of
    #: :class:`~pcapkit.protocols.link.ethernet.Ethernet` is ``Link``. However,
    #: certain protocols are not in any layer, such as
    #: :class:`~pcapkit.protocols.misc.raw.Raw`, and thus its layer is :obj:`None`.
    __layer__: 'Optional[Literal["Link", "Internet", "Transport", "Application"]]' = None

    #: Protocol index mapping for decoding next layer, c.f.
    #: :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    #: The values should be a tuple representing the module name and class name,
    #: or a :class:`Protocol` subclass.
    __proto__: 'DefaultDict[int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]' = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
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
    def info(self) -> '_PT':
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
    def payload(self) -> 'ProtocolBase':
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
    def packet(self) -> 'Data_Packet':
        """Data_Packet data of the protocol."""
        try:
            return self._read_packet(header=self.length)
        except UnsupportedCall:
            return Data_Packet(
                header=b'',
                payload=self._read_packet(),
            )

    # schema data
    @cached_property
    def schema(self) -> '_ST':
        """Schema data of the protocol."""
        return self.__header__

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[str, ...]':
        """Index ID of the protocol.

        Returns:
            By default, it returns the name of the protocol. In certain cases,
            the method may return multiple values.

        See Also:
            :meth:`pcapkit.protocols.protocol.Protocol.__getitem__`

        """
        return (cls.__name__,)

    @abc.abstractmethod
    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> '_PT':
        """Read (parse) packet data.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """

    @abc.abstractmethod
    def make(self, **kwargs: 'Any') -> '_ST':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Curated protocol schema data.

        """

    def pack(self, **kwargs: 'Any') -> 'bytes':
        """Pack (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Notes:
            We used a special keyword argument ``__packet__`` to pass the
            global packet data to underlying methods. This is useful when
            the packet data is not available in the current instance.

        """
        self.__header__ = self.make(**kwargs)
        packet = kwargs.get('__packet__', {})  # packet data
        return self.__header__.pack(packet)

    def unpack(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> '_PT':
        """Unpack (parse) packet data.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Notes:
            We used a special keyword argument ``__packet__`` to pass the
            global packet data to underlying methods. This is useful when
            the packet data is not available in the current instance.

        """
        if cast('Optional[_ST]', self.__header__) is None:
            packet = kwargs.get('__packet__', {})  # packet data
            self.__header__ = cast('_ST', self.__schema__.unpack(self._file, length, packet))  # type: ignore[call-arg,misc]
        return self.read(length, **kwargs)

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
    def unquote(url: str, *, encoding: 'str' = 'utf-8',
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
    def expand_comp(value: 'str | ProtocolBase | Type[ProtocolBase]') -> 'tuple':
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
        if isinstance(value, type) and issubclass(value, ProtocolBase):
            comp = (value, *(name.upper() for name in value.id()))
        elif isinstance(value, ProtocolBase):
            comp = (type(value), *(name.upper() for name in value.id()))
        else:
            from pcapkit.protocols import __proto__ as protocols_registry  # pylint: disable=import-outside-toplevel # isort: skip

            if (proto := protocols_registry.get(value.upper())) is not None:
                comp = (proto, *(name.upper() for name in proto.id()))
            else:
                comp = (value.upper(),)
        return comp

    @classmethod
    def analyze(cls, proto: 'int', payload: 'bytes', **kwargs: 'Any') -> 'ProtocolBase':
        """Analyse packet payload.

        Args:
            proto: Protocol registry number.
            payload: Packet payload.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed payload as a :class:`~pcapkit.protocols.protocol.Protocol`
            instance.

        """
        protocol = cls.__proto__[proto]
        if isinstance(protocol, ModuleDescriptor):
            protocol = protocol.klass
            cls.__proto__[proto] = protocol  # update mapping upon import

        payload_io = io.BytesIO(payload)
        try:
            report = protocol(payload_io, len(payload), **kwargs)  # type: ignore[abstract]
        except Exception as exc:
            if isinstance(exc, StructError) and exc.eof:  # pylint: disable=no-member
                from pcapkit.protocols.misc.null import NoPayload as protocol  # pylint: disable=import-outside-toplevel # isort: skip
            else:
                from pcapkit.protocols.misc.raw import Raw as protocol  # pylint: disable=import-outside-toplevel # isort: skip
            # error = traceback.format_exc(limit=1).strip().rsplit(os.linesep, maxsplit=1)[-1]

            # log error
            #logger.error(str(exc), exc_info=exc, stack_info=DEVMODE, stacklevel=stacklevel())

            report = protocol(payload_io, len(payload), **kwargs)  # type: ignore[abstract]
        return report

    @classmethod
    def register(cls, code: 'int', protocol: 'ModuleDescriptor | Type[ProtocolBase]') -> 'None':
        r"""Register a new protocol class.

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: protocol code
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.Protocol` subclass

        """
        if isinstance(protocol, ModuleDescriptor):
            protocol = protocol.klass
        if not issubclass(protocol, ProtocolBase):
            raise RegistryError(f'protocol must be a Protocol subclass, not {protocol!r}')
        if code in cls.__proto__:
            warn(f'protocol {code} already registered, overwriting', RegistryWarning)
        cls.__proto__[code] = protocol

    @classmethod
    def from_schema(cls, schema: '_ST | dict[str, Any]') -> 'Self':
        """Create protocol instance from schema.

        Args:
            schema: Protocol schema.

        Returns:
            Protocol instance.

        """
        if not isinstance(schema, Schema):
            schema = cast('_ST', cls.__schema__.from_dict(schema))

        self = cls.__new__(cls)
        self.__header__ = schema

        # initialize protocol instance
        self.__init__(bytes(schema), len(schema))  # type: ignore[misc]

        return self

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.

        Returns:
            Protocol instance.

        """
        if not isinstance(data, Data):
            data = cast('_PT', cls.__data__.from_dict(data))

        self = cls.__new__(cls)
        kwargs = self._make_data(data)

        # initialize protocol instance
        self.__init__(**kwargs)  # type: ignore[misc]

        return self

    ##########################################################################
    # Data models.
    ##########################################################################

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'Self':  # pylint: disable=unused-argument
        self = super().__new__(cls)

        # NOTE: Assign this attribute after ``__new__`` to avoid shared memory
        # reference between instances.
        self.__cached__ = {}
        self.__header__ = None  # type: ignore[assignment]

        return self

    @overload
    def __init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., **kwargs: 'Any') -> 'None': ...
    @overload
    def __init__(self, **kwargs: 'Any') -> 'None': ...

    def __init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'None':
        """Initialisation.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            _layer (str): Parse packet until ``_layer``
                (:attr:`self._exlayer <pcapkit.protocols.protocol.Protocol._exlayer>`).
            _protocol (Union[str, Protocol, Type[Protocol]]): Parse packet until ``_protocol``
                (:attr:`self._exproto <pcapkit.protocols.protocol.Protocol._exproto>`).
            **kwargs: Arbitrary keyword arguments.

        """
        #logger.debug('%s(file, %s, **%s)', type(self).__name__, length, kwargs)

        #: int: File pointer.
        self._seekset = io.SEEK_SET  # type: int
        #: str: Parse packet until such layer.
        self._exlayer = kwargs.pop('_layer', None)  # type: Optional[str]
        #: str: Parse packet until such protocol.
        self._exproto = kwargs.pop('_protocol', None)  # type: Optional[str | ProtocolBase | Type[ProtocolBase]]
        #: bool: If terminate parsing next layer of protocol.
        self._sigterm = self._check_term_threshold()

        # post-init customisations
        self.__post_init__(file, length, **kwargs)  # type: ignore[arg-type]

        # inject packet payload to the info dict
        self._info.__update__(packet=self.packet.payload)

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None,
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
            _data = self.pack(**kwargs)
        else:
            _data = file if isinstance(file, bytes) else file.read(length)  # type: ignore[arg-type]

        #: bytes: Raw packet data.
        self._data = _data
        #: io.BytesIO: Source packet stream.
        self._file = io.BytesIO(self._data)
        #: pcapkit.protocols.data.data.Data: Parsed packet data.
        self._info = self.unpack(length, **kwargs)

    def __init_subclass__(cls, /, schema: 'Optional[Type[_ST]]' = None,
                          data: 'Optional[Type[_PT]]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialisation for subclasses.

        Args:
            schema: Schema class.
            data: Data class.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        This method is called when a subclass of :class:`Protocol` is defined.
        It is used to set the :attr:`self.__schema__ <pcapkit.protocols.protocol.Protocol.__schema__>`
        attribute of the subclass.

        Notes:
            When ``schema`` and/or ``data`` is not specified, the method will first
            try to find the corresponding class in the
            :mod:`~pcapkit.protocols.schema` and :mod:`~pcapkit.protocols.data`
            modules respectively. If the class is not found, the default
            :class:`~pcapkit.protocols.schema.schema.Schema_Raw` and
            :class:`~pcapkit.protocols.data.data.Data_Raw` classes will be used.

        """
        super().__init_subclass__()

        if schema is None:
            schema = cast('Type[_ST]', getattr(schema_module, cls.__name__, Schema_Raw))
        if data is None:
            data = cast('Type[_PT]', getattr(data_module, cls.__name__, Data_Raw))

        cls.__schema__ = schema
        cls.__data__ = data

    def __repr__(self) -> 'str':
        """Returns representation of parsed protocol data.

        Example:
            >>> protocol
            <Frame alias='...' frame=(..., packet=b'...', sethernet=..., protocols='Ethernet:IPv6:Raw')>

        """
        if (cached := self.__cached__.get('__repr__')) is not None:
            return cached

        # cache and return
        repr_ = f'<{self.alias} {self.info_name}={self._info!r}>'

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

    def __iter__(self) -> 'IO[bytes]':
        """Iterate through :attr:`self._data <pcapkit.protocols.protocol.Protocol._data>`."""
        return io.BytesIO(self._data)

    def __getitem__(self, key: 'str | Protocol | Type[Protocol]') -> 'ProtocolBase':
        """Subscription (``getitem``) support.

        * If ``key`` is a :class:`~pcapkit.protocols.protocol.Protocol` object,
          the method will fetch its indexes (:meth:`self.id <pcapkit.protocols.protocol.Protocol.id>`).
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
        if isinstance(other, type) and issubclass(other, ProtocolBase):
            return cls is other
        if isinstance(other, ProtocolBase):
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

    def _get_payload(self) -> 'bytes':
        """Get payload from :attr:`self.__header__ <Protocol.__header__>`.

        Returns:
            Payload of :attr:`self.__header__ <Protocol.__header__>` as :obj:`bytes`.

        See Also:
            This is a wrapper function for :meth:`pcapkit.protocols.schema.schema.Schema.get_payload`.

        """
        return self.__header__.get_payload()

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
    def _read_packet(self, *, header: 'int', payload: 'Optional[int]' = ..., discard: 'Literal[False]' = ...) -> 'Data_Packet': ...  # pylint: disable=line-too-long

    @seekset  # type: ignore[misc]
    def _read_packet(self, length: 'Optional[int]' = None, *, header: 'Optional[int]' = None,
                     payload: 'Optional[int]' = None, discard: bool = False) -> 'bytes | Data_Packet':
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
          :class:`~pcapkit.protocols.data.protocol.Packet` object.

        """
        if header is not None:
            data_header = self._read_fileng(header)
            data_payload = self._read_fileng(payload)
            if discard:
                return data_payload
            return Data_Packet(
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
    @overload
    @classmethod
    def _make_index(cls, name: 'str | int | StdlibEnum | AenumEnum', default: 'Optional[int]' = ..., *,
                    namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = ...,
                    reversed: 'bool' = ..., pack: 'Literal[False]' = ...) -> 'int': ...

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
        if isinstance(name, (enum.Enum, aenum.Enum)):
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

    @classmethod
    def _make_data(cls, data: 'Data') -> 'dict[str, Any]':
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return data.to_dict()

    @classmethod
    def _make_payload(cls, data: 'Data') -> 'ProtocolBase':
        """Create payload from ``data`` for protocol construction.

        This method uses ``__next_type__`` and ``__next_name__`` to
        determine the payload type and name. If either of them is
        :data:`None`, a :class:`~pcapkit.protocols.misc.null.NoPayload`
        instance will be returned. Otherwise, the payload will be
        constructed by :meth:`Protocol.from_data <pcapkit.protocols.protocol.Protocol.from_data>`.

        Args:
            data: protocol data

        Returns:
            Payload for protocol construction.

        """
        proto = cast('Optional[Type[Protocol]]', data.get('__next_type__'))
        if proto is None or not (isinstance(proto, type) and issubclass(proto, ProtocolBase)):
            from pcapkit.protocols.misc.null import \
                NoPayload  # pylint: disable=import-outside-toplevel
            return NoPayload()

        name = cast('Optional[str]', data.get('__next_name__'))
        if name is None:
            from pcapkit.protocols.misc.null import \
                NoPayload  # pylint: disable=import-outside-toplevel
            return NoPayload()

        return proto.from_data(data[name])

    def _decode_next_layer(self, dict_: '_PT', proto: 'int', length: 'Optional[int]' = None, *,
                           packet: 'Optional[dict[str, Any]]' = None) -> '_PT':
        r"""Decode next layer protocol.

        Arguments:
            dict\_: info buffer
            proto: next layer protocol index
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <Protocol.unpack>`)

        Returns:
            Current protocol with next layer extracted.

        Notes:
            We added a new key ``__next_type__`` to ``dict_`` to store the
            next layer protocol type, and a new key ``__next_name__`` to
            store the next layer protocol name. These two keys will **NOT**
            be included when :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` is called.

        """
        next_ = cast('ProtocolBase', self._import_next_layer(proto, length, packet=packet))  # type: ignore[misc,call-arg,redundant-cast]
        info, chain = next_.info, next_.protochain

        # make next layer protocol name
        layer = next_.info_name
        # proto = next_.__class__.__name__

        # write info and protocol chain into dict
        dict_.__update__({
            layer: info,
            '__next_type__': type(next_),
            '__next_name__': layer,
        })
        self._next = next_  # pylint: disable=attribute-defined-outside-init
        self._protos = ProtoChain(self.__class__, self.alias, basis=chain)  # pylint: disable=attribute-defined-outside-init
        return dict_

    @beholder
    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,
                           packet: 'Optional[dict[str, Any]]' = None) -> 'ProtocolBase':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <Protocol.unpack>`)

        Returns:
            Instance of next layer.

        """
        if TYPE_CHECKING:
            protocol: 'Type[ProtocolBase]'

        file_ = self._get_payload()
        if length is None:
            length = len(file_)

        if length == 0:
            from pcapkit.protocols.misc.null import NoPayload as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.misc.raw import Raw as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        else:
            protocol = self.__proto__[proto]  # type: ignore[assignment]
            if isinstance(protocol, ModuleDescriptor):
                protocol = protocol.klass  # type: ignore[unreachable]
                self.__proto__[proto] = protocol  # update mapping upon import

        next_ = protocol(file_, length, alias=proto, packet=packet,
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


class Protocol(ProtocolBase, Generic[_PT, _ST]):
    """Abstract base class for all protocol family."""

    def __init_subclass__(cls, /, schema: 'Optional[Type[_ST]]' = None,
                          data: 'Optional[Type[_PT]]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialisation for subclasses.

        Args:
            schema: Schema class.
            data: Data class.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        This method is called when a subclass of :class:`Protocol` is defined.
        It is used to set the :attr:`self.__schema__ <pcapkit.protocols.protocol.Protocol.__schema__>`
        attribute of the subclass.

        Notes:
            When ``schema`` and/or ``data`` is not specified, the method will first
            try to find the corresponding class in the
            :mod:`~pcapkit.protocols.schema` and :mod:`~pcapkit.protocols.data`
            modules respectively. If the class is not found, the default
            :class:`~pcapkit.protocols.schema.schema.Schema_Raw` and
            :class:`~pcapkit.protocols.data.data.Data_Raw` classes will be used.

        This method also registers the subclass to the protocol registry,
        i.e., :attr:`pcapkit.protocols.__proto__`.

        See Also:
            For more information on the registry, please refer to
            :func:`pcapkit.foundation.registry.protocols.register_protocol`.

        """
        from pcapkit.foundation.registry.protocols import register_protocol
        register_protocol(cls)

        return super().__init_subclass__(schema, data, *args, **kwargs)
