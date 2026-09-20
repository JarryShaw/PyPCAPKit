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

from pcapkit.corekit.context import ContextRegistry
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols import data as data_module
from pcapkit.protocols import schema as schema_module
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.misc.raw import Raw as Data_Raw
from pcapkit.protocols.data.protocol import Packet as Data_Packet
from pcapkit.protocols.schema.misc.raw import Raw as Schema_Raw
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.chardet import detect
from pcapkit.utilities.compat import cached_property
from pcapkit.utilities.decorators import beholder, seekset
from pcapkit.utilities.exceptions import (ProtocolNotFound, ProtocolNotImplemented, RegistryError,
                                          StructError, UnsupportedCall)
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import IO, Any, Callable, DefaultDict, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal, Self

    from pcapkit.corekit.context import ProtocolContext

__all__ = ['ProtocolBase']

_PT = TypeVar('_PT', bound='Data')
_ST = TypeVar('_ST', bound='Schema')
_CTX = TypeVar('_CTX', bound='ProtocolContext')
_VT = TypeVar('_VT')

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

    #: Static dictionary cache for imported protocol modules.
    _MODULE_CACHE: 'dict[str, Type[ProtocolBase]]' = {}

    #: Caller supplied parsing context, c.f. :mod:`pcapkit.corekit.context`.
    #: :meth:`self.__init__ <Protocol.__init__>` replaces this with a real
    #: :class:`~pcapkit.corekit.context.ContextRegistry`; the class level
    #: :data:`None` is what an instance built without going through
    #: ``__init__`` -- e.g. ``object.__new__(SomeProtocol)`` -- sees, so that
    #: reading it is always safe.
    _exctx: 'Optional[ContextRegistry]' = None

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

    # caller supplied parsing context
    @property
    def context(self) -> 'ContextRegistry':
        """Caller supplied parsing context.

        See Also:
            :mod:`pcapkit.corekit.context` for what this channel is for, and
            :meth:`self._get_context <ProtocolBase._get_context>` for how a
            protocol implementation reaches its own entry.

        """
        return ContextRegistry.make(self._exctx)

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
        charset = encoding or detect(byte)
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
        protocol = cls._lookup_next_layer(cls.__proto__, proto)

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

    @overload  # pragma: no cover
    def __init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., **kwargs: 'Any') -> 'None': ...
    @overload  # pragma: no cover
    def __init__(self, **kwargs: 'Any') -> 'None': ...

    def __init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'None':
        """Initialisation.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            _layer (str): Parse packet until ``_layer``
                (:attr:`self._exlayer <pcapkit.protocols.protocol.Protocol._exlayer>`).
                While parsing, the un-prefixed ``layer`` is accepted as well --
                see the note below.
            _protocol (Union[str, Protocol, Type[Protocol]]): Parse packet until ``_protocol``
                (:attr:`self._exproto <pcapkit.protocols.protocol.Protocol._exproto>`).
                While parsing, the un-prefixed ``protocol`` is accepted as well --
                see the note below.
            packet (dict[str, Any]): Packet context of the enclosing layer, as
                handed over by
                :meth:`self._import_next_layer <ProtocolBase._import_next_layer>`.
                While parsing, it is republished as ``__packet__`` so that
                :meth:`self.unpack <Protocol.unpack>` -- and through it the
                schema -- can see it; see the note below.
            __context__ (Union[ContextRegistry, ProtocolContext, Mapping[str, ProtocolContext], Iterable[ProtocolContext]]):
                Caller supplied parsing context (:attr:`self._exctx <pcapkit.protocols.protocol.Protocol._exctx>`),
                c.f. :mod:`pcapkit.corekit.context`. It is consumed here rather
                than being forwarded to :meth:`self.read <Protocol.read>`, and is
                propagated to nested layers by
                :meth:`self._import_next_layer <ProtocolBase._import_next_layer>`.
            **kwargs: Arbitrary keyword arguments.

        Note:
            Three of the keywords above are *out-of-band*: they configure the
            parse rather than describing the packet, and every one of them is
            consumed here, at the one point each of a protocol's producers passes
            through. That is deliberate, and it is what the normalisation below
            relies on -- fixing a spelling here fixes it for the engines, for all
            four :meth:`_import_next_layer <ProtocolBase._import_next_layer>`
            implementations, and for any third party protocol that copied their
            shape, rather than one call site at a time.

        """
        #logger.debug('%s(file, %s, **%s)', type(self).__name__, length, kwargs)

        # Whether this instantiation parses an existing packet, as opposed to
        # constructing a new one. ``file`` is the discriminator the rest of this
        # method already turns on: ``__post_init__`` reads the stream when there
        # is one and calls ``self.pack(**kwargs)`` when there is not. It matters
        # below because ``layer``, ``protocol`` and ``packet`` are out-of-band
        # only while parsing -- on the construction path they are ordinary
        # ``make()`` arguments, and consuming them there would silently drop the
        # value being constructed.
        parsing = file is not None

        #: int: File pointer.
        self._seekset = io.SEEK_SET  # type: int
        #: str: Parse packet until such layer.
        self._exlayer = kwargs.pop('_layer', None)  # type: Optional[str]
        #: str: Parse packet until such protocol.
        self._exproto = kwargs.pop('_protocol', None)  # type: Optional[str | ProtocolBase | Type[ProtocolBase]]

        # NOTE: The parse limits are documented here as ``_layer`` and
        # ``_protocol``, but no producer in the tree spells them that way. The
        # engines build the outermost protocol with ``layer=``/``protocol=``
        # (``pcapkit.foundation.engines.pcap.PCAP.read_frame`` and
        # ``pcapkit.foundation.engines.pcapng.PCAPNG.read_frame``), every
        # ``_import_next_layer`` recurses into the next one the same way, and the
        # un-prefixed pair is also the public spelling that
        # ``pcapkit.extract(layer=..., protocol=...)`` and the CLI's ``-L``/``-P``
        # use. Both were therefore dropped into ``**kwargs`` and ignored, so
        # neither option did anything at all; see GH-356. Accepting both
        # spellings is what makes them work, and the prefixed one still wins so
        # that a caller which reads this docstring is not overridden by a limit
        # its parent happened to be forwarding.
        if parsing:
            layer = kwargs.pop('layer', None)
            protocol = kwargs.pop('protocol', None)
            if self._exlayer is None:
                self._exlayer = layer
            if self._exproto is None:
                self._exproto = protocol

        # NOTE: ``Extractor.__init__`` substitutes the strings ``'none'`` and
        # ``'null'`` for an omitted ``layer``/``protocol``
        # (``pcapkit.foundation.extraction.Extractor.__init__``), and
        # ``pcapkit.interface.core.extract`` does the same for ``layer``. They are
        # sentinels meaning "no limit", so recognise them as such instead of
        # carrying them into ``_check_term_threshold`` on every protocol of every
        # packet, where they would be compared against real protocol names.
        if isinstance(self._exlayer, str) and self._exlayer.lower() == 'none':
            self._exlayer = None
        if isinstance(self._exproto, str) and self._exproto.lower() == 'null':
            self._exproto = None

        #: pcapkit.corekit.context.ContextRegistry: Caller supplied parsing context.
        # NOTE: Every nested layer normalises the context it was handed, so an
        # already-normalised registry is adopted as-is: ``make()`` copies, and
        # paying for a dict copy per protocol in a capture buys nothing when the
        # contexts are shared regardless.
        __context__ = kwargs.pop('__context__', None)
        self._exctx = (__context__ if isinstance(__context__, ContextRegistry)
                       else ContextRegistry.make(__context__))  # type: ContextRegistry
        #: bool: If terminate parsing next layer of protocol.
        self._sigterm = self._check_term_threshold()

        # NOTE: The enclosing layer's packet context arrives as ``packet=`` -- the
        # spelling ``_import_next_layer`` uses -- but the schema layer reads it
        # from ``__packet__`` (``self.unpack`` below, and the ``pack``/``unpack``
        # overrides of ``Frame`` and ``PCAPNG``). Nothing bridged the two, so a
        # schema's ``unpack``/``post_process`` always saw an empty dict however
        # much the outer layer had put in it: an ``IPv6`` source address never
        # reached the HOPOPT MPL option that RFC 7731 elides from the wire, and a
        # destination address never reached the RPL source route header that
        # RFC 6554 needs it to decompress. Republish it here, for the same reason
        # the limits above are normalised here. See GH-382.
        #
        # A copy rather than the dict itself: ``Schema.unpack`` writes every field
        # it reads into the context it is given, plus its own ``__length__`` and
        # ``__option_padding__`` bookkeeping, and the IPv6 extension header walk
        # hands one dict to each header in turn. Sharing it would leave one
        # header's fields visible to the next, where a ``ConditionalField`` test
        # or a length callback could read a sibling's stale value instead of
        # failing. ``Schema.unpack`` already isolates its own per-field contexts
        # the same way.
        if parsing and '__packet__' not in kwargs and isinstance(kwargs.get('packet'), dict):
            kwargs['__packet__'] = dict(kwargs['packet'])

        # post-init customisations
        self.__post_init__(file, length, **kwargs)  # type: ignore[arg-type]

        # inject packet payload to the info dict
        self._info.__update__(packet=self.packet.payload)

    @overload  # pragma: no cover
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., **kwargs: 'Any') -> 'None': ...
    @overload  # pragma: no cover
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

    def _get_context(self, cls: 'Optional[Type[_CTX]]' = None) -> 'Optional[_CTX]':
        """Get the caller supplied context for this protocol, if any.

        The lookup is keyed on :meth:`self.id <ProtocolBase.id>`, so a
        protocol finds its own context without knowing how the caller spelled
        the registry.

        Args:
            cls: Expected context class; when given, a context registered
                under this protocol's name but of another type is ignored
                rather than returned for the implementation to trip over.

        Returns:
            The matching context, or :data:`None` when the caller supplied
            none.

        See Also:
            :mod:`pcapkit.corekit.context`

        """
        registry = self._exctx
        if registry is None:
            return None
        return registry.match(self.id(), cls)

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

    @overload  # pragma: no cover
    def _read_packet(self, length: 'Optional[int]' = ..., *, header: 'None' = ...) -> 'bytes': ...
    @overload  # pragma: no cover
    def _read_packet(self, *, header: 'int', payload: 'Optional[int]' = ..., discard: 'Literal[True]') -> 'bytes': ...
    @overload  # pragma: no cover
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

    @overload  # pragma: no cover
    @classmethod
    def _make_index(cls, name: 'int | StdlibEnum | AenumEnum', *, pack: 'Literal[False]' = ...) -> 'int': ...
    @overload  # pragma: no cover
    @classmethod
    def _make_index(cls, name: 'int | StdlibEnum | AenumEnum', *, pack: 'Literal[True]',
                    size: 'int' = ..., signed: 'bool' = ..., lilendian: 'bool' = ...) -> 'bytes': ...
    @overload  # pragma: no cover
    @classmethod
    def _make_index(cls, name: 'str', default: 'Optional[int]' = ..., *,
                    namespace: 'Type[StdlibEnum] | Type[AenumEnum]', pack: 'Literal[False]' = ...) -> 'int': ...
    @overload  # pragma: no cover
    @classmethod
    def _make_index(cls, name: 'str', default: 'Optional[int]' = ..., *,
                    namespace: 'Type[StdlibEnum] | Type[AenumEnum]', pack: 'Literal[True]',
                    size: 'int' = ..., signed: 'bool' = ..., lilendian: 'bool' = ...) -> 'bytes': ...
    @overload  # pragma: no cover
    @classmethod
    def _make_index(cls, name: 'str', default: 'Optional[int]' = ..., *, namespace: 'dict[int, str]',
                    reversed: 'Literal[False]' = ...,  # pylint: disable=redefined-builtin
                    pack: 'Literal[False]' = ...) -> 'int': ...
    @overload  # pragma: no cover
    @classmethod
    def _make_index(cls, name: 'str', default: 'Optional[int]' = ..., *, namespace: 'dict[int, str]',
                    reversed: 'Literal[False]' = ...,  # pylint: disable=redefined-builtin
                    pack: 'Literal[True]', size: 'int' = ..., signed: 'bool' = ...,
                    lilendian: 'bool' = ...) -> 'bytes': ...
    @overload  # pragma: no cover
    @classmethod
    def _make_index(cls, name: 'str', default: 'Optional[int]' = ..., *, namespace: 'dict[str, int]',
                    reversed: 'Literal[True]',  # pylint: disable=redefined-builtin
                    pack: 'Literal[False]' = ...) -> 'int': ...
    @overload  # pragma: no cover
    @classmethod
    def _make_index(cls, name: 'str', default: 'Optional[int]' = ..., *, namespace: 'dict[str, int]',
                    reversed: 'Literal[True]',  # pylint: disable=redefined-builtin
                    pack: 'Literal[True]', size: 'int' = ..., signed: 'bool' = ...,
                    lilendian: 'bool' = ...) -> 'bytes': ...
    @overload  # pragma: no cover
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
                    # Caught by the handler immediately below and converted, so
                    # this never escapes -- it is a jump to the shared "name is
                    # not in namespace" path, not a stdlib exception leaking out
                    # of the library. A pcapkit exception here would log at
                    # CRITICAL for something that is handled two lines later.
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

    @staticmethod
    def _lookup_registry(registry: 'DefaultDict[Any, _VT]', code: 'Any') -> '_VT':
        """Look up a dispatch registry entry without recording a miss.

        Arguments:
            registry: dispatch registry to read, i.e. :attr:`self.__proto__
                <ProtocolBase.__proto__>` or one of the per-protocol
                ``__option__`` / ``__chunk__`` / ``__block__`` family. Passed in
                rather than read from the class, so that a caller reaching the
                registry through an instance keeps doing so.
            code: registry key to look up, i.e. the wire code being dispatched on

        Returns:
            The entry registered for ``code``, or the fallback ``registry``
            declares when ``code`` is not registered.

        Important:
            Every one of these registries is a :class:`collections.defaultdict`
            held on a *class* attribute, shared by every instance of the class in
            the process. So ``registry[code]`` inserts each code it misses, and
            parsing one packet carrying an unrecognised code is enough to grow
            the registry permanently.

            The inserted value is whatever the default factory would have
            produced anyway, so the entry buys nothing. It costs a spurious
            "already registered" warning from the next genuine ``register`` call
            for that code, and it makes "is this code registered?"
            unanswerable by inspection, since the answer depends on what has
            been parsed. The fallback is therefore read from the default factory
            directly rather than through a lookup that records it.

        """
        if code in registry:
            return registry[code]
        return cast('Callable[[], _VT]', registry.default_factory)()

    @staticmethod
    def _lookup_next_layer(registry: 'DefaultDict[int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]',
                           proto: 'int') -> 'Type[ProtocolBase]':
        """Look up the protocol class registered for a next layer code.

        Arguments:
            registry: next layer protocol registry, i.e. :attr:`self.__proto__
                <ProtocolBase.__proto__>`. Passed in rather than read from the
                class, so that a caller reaching the registry through an
                instance keeps doing so.
            proto: next layer protocol index

        Returns:
            The class registered for ``proto``, or the fallback ``registry``
            declares -- normally :class:`~pcapkit.protocols.misc.raw.Raw` -- when
            ``proto`` is not registered.

        Important:
            The lookup itself is :meth:`self._lookup_registry
            <ProtocolBase._lookup_registry>`, so a miss does not grow the shared
            registry. What this adds is the next-layer-specific resolution step:
            a registered code may hold a
            :class:`~pcapkit.corekit.module.ModuleDescriptor` rather than a
            class, and importing it is written back so the import happens once.

            That write-back is deliberately confined to a *hit*. Memoising the
            fallback's resolution under ``proto`` would be exactly the insertion
            :meth:`self._lookup_registry <ProtocolBase._lookup_registry>` exists
            to avoid.

        """
        protocol = ProtocolBase._lookup_registry(registry, proto)
        if isinstance(protocol, ModuleDescriptor):
            key = f'{protocol.module}.{protocol.name}'
            if key not in ProtocolBase._MODULE_CACHE:
                ProtocolBase._MODULE_CACHE[key] = protocol.klass
            klass = ProtocolBase._MODULE_CACHE[key]
            
            # a descriptor can also come back from the default factory, and that
            # one has no key to memoise under -- writing it back would recreate
            # the insertion-on-miss this exists to avoid
            if proto in registry:
                registry[proto] = klass  # update mapping upon import
            return klass
        return protocol

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
            if 'pcapkit.protocols.misc.null.NoPayload' not in ProtocolBase._MODULE_CACHE:
                from pcapkit.protocols.misc.null import NoPayload  # isort: skip # pylint: disable=import-outside-toplevel
                ProtocolBase._MODULE_CACHE['pcapkit.protocols.misc.null.NoPayload'] = NoPayload
            protocol = ProtocolBase._MODULE_CACHE['pcapkit.protocols.misc.null.NoPayload']
        elif self._sigterm:
            if 'pcapkit.protocols.misc.raw.Raw' not in ProtocolBase._MODULE_CACHE:
                from pcapkit.protocols.misc.raw import Raw  # isort: skip # pylint: disable=import-outside-toplevel
                ProtocolBase._MODULE_CACHE['pcapkit.protocols.misc.raw.Raw'] = Raw
            protocol = ProtocolBase._MODULE_CACHE['pcapkit.protocols.misc.raw.Raw']
        else:
            protocol = self._lookup_next_layer(self.__proto__, proto)

        next_ = protocol(file_, length, alias=proto, packet=packet,
                         layer=self._exlayer, protocol=self._exproto,
                         __context__=self._exctx)  # type: ignore[abstract]
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
