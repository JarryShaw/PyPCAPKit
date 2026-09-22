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
import difflib
import enum
import functools
import inspect
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
from pcapkit.utilities.compat import cached_property, final
from pcapkit.utilities.decorators import beholder, seekset
from pcapkit.utilities.exceptions import (ProtocolNotFound, ProtocolNotImplemented, RegistryError,
                                          StructError, UnsupportedCall)
from pcapkit.utilities.warnings import RegistryWarning, UnknownFieldWarning, warn

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

#: Keywords that configure the construction rather than naming a field, and are
#: therefore consumed by :meth:`ProtocolBase.__init__
#: <pcapkit.protocols.protocol.ProtocolBase.__init__>` or by the schema layer
#: instead of by a :meth:`make <pcapkit.protocols.protocol.Protocol.make>`. They
#: are declared by no signature, so :func:`_declared_keywords` cannot find them
#: and they are listed here instead.
#:
#: ``packet`` is here because the library puts it there itself, rather than
#: because a caller might: :meth:`ProtocolBase.__init__
#: <pcapkit.protocols.protocol.ProtocolBase.__init__>` injects
#: ``packet=self.packet.payload`` into every parsed ``_info``, so the default
#: :meth:`ProtocolBase._make_data
#: <pcapkit.protocols.protocol.ProtocolBase._make_data>` -- which is
#: ``data.to_dict()`` -- carries it into the keywords that
#: :meth:`ProtocolBase.from_data <pcapkit.protocols.protocol.ProtocolBase.from_data>`
#: reconstructs from. Refusing it would make ``from_data`` fail on any protocol
#: whose ``make`` does not happen to declare a ``packet``, starting with
#: :class:`~pcapkit.protocols.misc.null.NoPayload`, which is reached for the
#: innermost layer of every packet. It is a field name for some protocols all the
#: same -- :meth:`HIP.make <pcapkit.protocols.internet.hip.HIP.make>` takes the
#: HIP packet *type* under that name -- and listing it here does not change how it
#: binds, only that it is never refused.
OUT_OF_BAND_KEYWORDS = frozenset({'_layer', '_protocol', '__context__',
                                  '__packet__', 'packet'})


@final
class _AbsentType:
    """Type of :data:`_Absent`, the absent-key sentinel.

    A distinct class rather than a bare :obj:`object` so that the sentinel has a
    name of its own in a traceback or a debugger, and so that a type checker has
    something to name where ``object()`` would give it nothing. It
    follows :class:`~pcapkit.corekit.fields.field.NoValueType`, which does the
    same job for an unset field default; this is a sibling of it rather than a
    reuse, since that one is documented as the default value of
    :attr:`FieldBase.default <pcapkit.corekit.fields.field.FieldBase.default>`
    and means "no value was given", not "this key is not here".

    """

    def __bool__(self) -> 'Literal[False]':
        """Return :obj:`False`."""
        return False

    def __repr__(self) -> 'str':
        """Return :obj:`str` representation of the sentinel."""
        return '<absent>'


#: _AbsentType: Absent-versus-:obj:`None` sentinel for reading ``__keywords__``
#: out of a class :attr:`~object.__dict__`, where :obj:`None` is a meaningful
#: value -- it is the opt-out that says the class cannot enumerate its keywords,
#: c.f. :attr:`ProtocolBase.__keywords__
#: <pcapkit.protocols.protocol.ProtocolBase.__keywords__>`. Never leaves this
#: module: it is read in :func:`_declared_keywords` and discarded there.
_Absent = _AbsentType()

#: Cache for :func:`_declared_keywords`, keyed by protocol class. A protocol's
#: signatures do not change after the class is created, and the walk below is
#: :math:`O(\\text{MRO} \\times \\text{methods})`, so it is done once per class
#: rather than once per constructed packet.
_DECLARED_KEYWORDS = {}  # type: dict[type, Optional[frozenset[str]]]

#: Methods that a construction keyword may legitimately be destined for. The
#: keywords handed to :class:`Protocol` are forwarded to all of them -- see
#: :meth:`ProtocolBase.__post_init__
#: <pcapkit.protocols.protocol.ProtocolBase.__post_init__>`, which passes the
#: same ``**kwargs`` to :meth:`pack <pcapkit.protocols.protocol.Protocol.pack>`
#: (and through it to ``make``) *and* to :meth:`unpack
#: <pcapkit.protocols.protocol.Protocol.unpack>` (and through it to ``read``).
_KEYWORD_CONSUMERS = ('make', 'read', 'pack', 'unpack', '__post_init__', '__init__')


def _declared_keywords(cls: 'type') -> 'Optional[frozenset[str]]':
    """Collect every keyword the protocol ``cls`` declares a parameter for.

    Args:
        cls: Protocol class to inspect.

    Returns:
        Names of every keyword-acceptable parameter declared by any of
        :data:`_KEYWORD_CONSUMERS` anywhere in the MRO of ``cls``, plus every
        entry of :attr:`ProtocolBase.__keywords__
        <pcapkit.protocols.protocol.ProtocolBase.__keywords__>` found there,
        plus :data:`OUT_OF_BAND_KEYWORDS`. :obj:`None` if ``cls`` *itself* sets
        ``__keywords__`` to :obj:`None`, meaning its keywords cannot be enumerated
        and are not to be checked -- inherited :obj:`None` does not count, for the
        reason given at the read below.

    The union is deliberately wider than the signature of ``cls.make`` alone,
    because a keyword reaching ``make`` is not necessarily *for* ``make``:
    :meth:`ProtocolBase.__post_init__
    <pcapkit.protocols.protocol.ProtocolBase.__post_init__>` hands one
    ``**kwargs`` to both the construction and the parse of the packet it has just
    constructed, so a keyword declared by ``read`` travels through ``make`` as
    well. :class:`~pcapkit.protocols.internet.hip.HIP` is the live example --
    :meth:`HIP.read <pcapkit.protocols.internet.hip.HIP.read>` declares
    ``extension`` and :meth:`HIP.make <pcapkit.protocols.internet.hip.HIP.make>`
    does not, yet :meth:`HIP.__post_init__
    <pcapkit.protocols.internet.hip.HIP.__post_init__>` forwards it to both.
    Rejecting on ``make`` alone would reject that, which is correct code.

    The walk covers the whole MRO rather than the most derived override of each
    method, for the same reason: a subclass that declares its own keyword and
    forwards the rest to its parent must not make the parent's keywords
    unreachable.

    """
    try:
        return _DECLARED_KEYWORDS[cls]
    except KeyError:
        pass

    unchecked = False
    names = set(OUT_OF_BAND_KEYWORDS)
    for klass in cls.__mro__:
        # NOTE: A keyword read out of ``**kwargs`` by name rather than declared
        # as a parameter is invisible to :func:`inspect.signature`, so the class
        # says so itself. Read per class in the MRO, for the same reason the
        # methods are: a subclass should not have to repeat its parents'.
        keywords = klass.__dict__.get('__keywords__', _Absent)
        if keywords is None:
            # NOTE: The :obj:`None` opt-out is *not* inherited, unlike a set,
            # which is unioned down the MRO. It describes how the class that
            # declares it dispatches, which is not a property its subclasses
            # share: :class:`~pcapkit.protocols.application.http.HTTP` cannot
            # enumerate its keywords because it forwards them to whichever of
            # :class:`HTTPv1 <pcapkit.protocols.application.httpv1.HTTP>` and
            # :class:`HTTPv2 <pcapkit.protocols.application.httpv2.HTTP>` the
            # ``version`` names -- but those two declare theirs in full, and
            # inheriting the opt-out would silently exempt the very classes that
            # can be checked. A subclass that dispatches in turn says so itself.
            if klass is cls:
                unchecked = True
        elif keywords is not _Absent:
            names.update(keywords)

        for method in _KEYWORD_CONSUMERS:
            # NOTE: Read from ``__dict__`` rather than with :func:`getattr`, so
            # that each class in the MRO contributes its *own* definition instead
            # of the most derived one over and over. An ``@overload``-decorated
            # stub is overwritten by the implementation that follows it, which is
            # what lands here.
            func = klass.__dict__.get(method)
            if func is None:
                continue

            try:
                signature = inspect.signature(func)
            except (TypeError, ValueError):  # pragma: no cover
                # NOTE: A C-implemented or otherwise unintrospectable callable is
                # skipped rather than fatal: failing to widen the accepted set is
                # a false rejection, so the safe move is to keep walking.
                continue

            for name, param in signature.parameters.items():
                if name in ('self', 'cls'):
                    continue
                if param.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD,
                                  inspect.Parameter.KEYWORD_ONLY):
                    names.add(name)

    declared = None if unchecked else frozenset(names)
    _DECLARED_KEYWORDS[cls] = declared
    return declared


def _check_construction_keywords(cls: 'type', kwargs: 'dict[str, Any]',
                                 strict: 'bool' = True) -> 'None':
    """Reject construction keywords that the protocol ``cls`` declares nowhere.

    Args:
        cls: Protocol class being constructed.
        kwargs: Keywords remaining after :meth:`ProtocolBase.__init__
            <pcapkit.protocols.protocol.ProtocolBase.__init__>` has consumed the
            out-of-band ones.
        strict: Whether an unexpected keyword is an error. :data:`True` for a
            caller's own construction; :data:`False` when the keywords were
            generated by :meth:`ProtocolBase._make_data
            <pcapkit.protocols.protocol.ProtocolBase._make_data>` rather than
            written by anybody -- see :meth:`ProtocolBase.from_data
            <pcapkit.protocols.protocol.ProtocolBase.from_data>`.

    Raises:
        UnsupportedCall: If ``strict`` and any keyword matches no parameter of
            :data:`_KEYWORD_CONSUMERS` anywhere in the MRO of ``cls``.

    Warns:
        UnknownFieldWarning: The same finding when not ``strict``.

    """
    declared = _declared_keywords(cls)
    if declared is None:
        return

    unexpected = sorted(key for key in kwargs if key not in declared)
    if not unexpected:
        return

    # NOTE: The whole point of the check is a misspelling, so name the neighbour
    # that was probably meant: ``seq`` for ``seq_no`` and ``ack_flag`` for
    # ``ack`` are both a :func:`difflib.get_close_matches` hit, and the message
    # is the only place the caller looks before reading the signature.
    report = []  # type: list[str]
    for key in unexpected:
        suggestions = difflib.get_close_matches(key, declared, n=1)
        report.append(f'{key!r} (did you mean {suggestions[0]!r}?)' if suggestions else repr(key))
    listed = ', '.join(report)

    if strict:
        raise UnsupportedCall(f'{cls.__name__}: unexpected keyword(s): {listed}')

    # NOTE: A warning rather than an error, because nobody typed these: they are
    # whatever ``_make_data`` returned, so the defect is a key of that mapping
    # disagreeing with the signature it is spread into, and the person who meets
    # it is not the person who can fix it. Raising would also turn three latent
    # defects of exactly that shape into a broken ``from_data`` -- ``Frame``
    # returns ``ts_src`` for ``ts_sec``, ``Header`` an undeclared
    # ``magic_number``, ``L2TPv2`` ``prio`` for ``priority`` -- each of which has
    # been losing that field in silence and each of which belongs to its own
    # change. This is what makes them audible meanwhile.
    #
    # No explicit ``stacklevel``: the default blames the innermost frame outside
    # :mod:`pcapkit`, which is the ``from_data`` call the reader wants to be
    # pointed at, and it stays right if the frames between here and there ever
    # change, where a hardcoded count would not. It is also what
    # :meth:`Schema.__update__ <pcapkit.protocols.schema.schema.Schema.__update__>`
    # passes for the warning this one is the counterpart of.
    warn(f'{cls.__name__}._make_data returned keyword(s) that no signature of '
         f'{cls.__name__} declares, so they are discarded: {listed}',
         UnknownFieldWarning)


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

    #: Construction keywords this protocol consumes out of ``**kwargs`` instead
    #: of declaring as a parameter, e.g. with ``kwargs.get('spam')`` in
    #: :meth:`read` -- as :meth:`ESP.read <pcapkit.protocols.internet.esp.ESP.read>`
    #: does with ``packet``. :func:`~pcapkit.protocols.protocol._declared_keywords`
    #: finds a protocol's keywords by reading its signatures, which cannot see
    #: such a name, so a protocol that consumes one names it here and the
    #: construction check of :meth:`__init__` accepts it. The union over the MRO
    #: is used, so a subclass need not repeat its parents' entries.
    #:
    #: Declaring the parameter is preferable where it is possible, since that is
    #: also what documents the keyword to the caller and to :mod:`inspect`. This
    #: is for the cases where it is not -- a keyword handled uniformly for a whole
    #: family of names, say -- and *not* a way to reopen the silence #617 closed:
    #: it is opt-in per class, so it can only ever exempt a name whose author
    #: wrote it down.
    #:
    #: :obj:`None` means the keywords cannot be enumerated at all and the check is
    #: skipped for this protocol. That is for a *dispatcher*, whose real signature
    #: belongs to a class chosen at call time:
    #: :meth:`HTTP.make <pcapkit.protocols.application.http.HTTP.make>` declares
    #: only ``version`` and forwards everything else to
    #: :meth:`HTTPv1.make <pcapkit.protocols.application.httpv1.HTTP.make>` or
    #: :meth:`HTTPv2.make <pcapkit.protocols.application.httpv2.HTTP.make>`
    #: depending on that value, so no set of names is right for it. Use it only
    #: for that shape; a protocol that forgoes the check gets the pre-#617
    #: behaviour back, and with it the silence. Unlike a set, the :obj:`None` is
    #: **not** inherited: a subclass of a dispatcher is checked normally unless it
    #: dispatches too and says so, because ``HTTPv1`` and ``HTTPv2`` declare their
    #: keywords in full and exempting them along with their base would forgo the
    #: check on the only two classes here that can have it.
    __keywords__: 'Optional[frozenset[str]]' = frozenset()

    #: Whether this instance is being rebuilt by :meth:`from_data` from a parsed
    #: data model, as against constructed from keywords somebody wrote. It governs
    #: only whether the construction keyword check of :meth:`__init__` raises or
    #: warns (#617), and is set for the duration of that call alone -- the class
    #: level :data:`False` is what every other code path sees, including an
    #: instance built without going through ``__init__`` at all.
    __reconstructing__: 'bool' = False

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

        Note:
            The ``**kwargs`` here absorbs the keywords that
            :meth:`ProtocolBase.__post_init__
            <pcapkit.protocols.protocol.ProtocolBase.__post_init__>` hands to the
            parse as well as to the construction, so an implementation is not
            expected to declare every keyword it is called with. It is *not* a
            place for a caller to put a keyword no signature declares: since
            #617, building a protocol *through its constructor* with such a
            keyword raises :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`
            from :meth:`ProtocolBase.__init__
            <pcapkit.protocols.protocol.ProtocolBase.__init__>` rather than
            discarding it.

        Warning:
            **Calling this method directly is not checked**, and still discards an
            undeclared keyword in silence. The check lives in
            :meth:`ProtocolBase.__init__
            <pcapkit.protocols.protocol.ProtocolBase.__init__>`, so it covers
            ``SomeProtocol(...)`` and the :meth:`pack` it leads to, but not
            ``SomeProtocol.make(...)`` on an instance obtained some other way --
            ``object.__new__(cls).make(**kwargs)`` is the idiom, used by this
            package's own tests and by :meth:`HTTP.make
            <pcapkit.protocols.application.http.HTTP.make>` to reach its versioned
            implementation. Covering it would mean interposing on every ``make``
            in the tree rather than on the one place their keywords converge, which
            is a larger change than #617 and deliberately not made here. Construct
            through the constructor to get the check.

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

        # NOTE: These keywords came out of ``_make_data``, not out of a caller, so
        # the construction keyword check of ``__init__`` (#617) warns here instead
        # of raising: a key of that mapping which disagrees with the signature it
        # is spread into is a defect in this protocol, and the caller of
        # ``from_data`` can do nothing about it. Set for the duration of the call
        # and removed afterwards, so an instance built this way is afterwards
        # indistinguishable from one built directly.
        self.__reconstructing__ = True
        try:
            # initialize protocol instance
            self.__init__(**kwargs)  # type: ignore[misc]
        finally:
            del self.__reconstructing__

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

        Raises:
            UnsupportedCall: When constructing (``file`` is :obj:`None`), if a
                keyword names no parameter of this protocol's :meth:`make`,
                :meth:`read`, :meth:`pack`, :meth:`unpack`,
                :meth:`__post_init__` or :meth:`__init__`, anywhere in the MRO,
                and is not listed in :attr:`__keywords__`. See #617; until then
                such a keyword was silently discarded. Parsing (``file`` is
                given) is unaffected.

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

        # NOTE: Construction only. A keyword that names no parameter of this
        # protocol is a mistake rather than a value, and until #617 it was
        # silently discarded: every ``make`` in the tree ends its signature with
        # ``**kwargs`` and never reads it, so the keyword reached the schema as
        # nothing at all and the field kept its default. The cost was measured on
        # #602, where ``TCP_BASE`` asked for ``seq=1`` -- which ``TCP.make``
        # spells ``seq_no`` -- and 25 generated fixture frames carried ``seq = 0``
        # with an empty ``warnings`` list to show for it. The schema layer has
        # never been that permissive: :meth:`Schema.__update__
        # <pcapkit.protocols.schema.schema.Schema.__update__>` warns
        # :exc:`~pcapkit.utilities.warnings.UnknownFieldWarning` for a field it
        # does not know, and this closes the asymmetry from the other end.
        #
        # Parsing is left alone. There, the keywords are not field values but
        # whatever the engines and the four ``_import_next_layer``
        # implementations forward -- ``alias``, ``packet``, and the limits
        # normalised above -- and a protocol has no way to know which of its
        # ancestors' keywords its parent chose to pass on. Nothing was ever lost
        # that way either: a dropped parse keyword changes how a packet is read,
        # not what the octets say.
        if not parsing:
            _check_construction_keywords(
                type(self), kwargs, strict=not self.__reconstructing__)

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
                          data: 'Optional[Type[_PT]]' = None,
                          code: 'Any' = None,
                          *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialisation for subclasses.

        Args:
            schema: Schema class.
            data: Data class.
            code: Next-layer dispatch registration key(s). :data:`None` (the
                default) skips registration entirely -- see below.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            UnsupportedCall: If any unrecognised class keyword is given.

        This method is called when a subclass of :class:`Protocol` is defined.
        It is used to set the :attr:`self.__schema__ <pcapkit.protocols.protocol.Protocol.__schema__>`
        attribute of the subclass, and, if ``code`` is given, to register the
        subclass into the next-layer dispatch registry (or registries) that
        ``code`` names -- e.g. :attr:`Link.__proto__
        <pcapkit.protocols.link.link.Link.__proto__>`.

        Notes:
            When ``schema`` and/or ``data`` is not specified, the method will first
            try to find the corresponding class in the
            :mod:`~pcapkit.protocols.schema` and :mod:`~pcapkit.protocols.data`
            modules respectively. If the class is not found, the default
            :class:`~pcapkit.protocols.schema.misc.raw.Raw` and
            :class:`~pcapkit.protocols.data.misc.raw.Raw` classes will be used.

        Dispatch registration is **opt-in**, exactly like the ``name=``/``protocol=``/
        ``fmt=`` keywords of :class:`~pcapkit.foundation.engines.engine.Engine`,
        :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly`,
        :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` and
        :class:`~pcapkit.dumpkit.common.Dumper`. Omitting ``code`` is a
        deliberate, documented way for a subclass to decline registration, not
        an oversight -- it is exactly what every built-in protocol class does
        today, since the built-in dispatch tables (e.g. ``Link.__proto__``)
        are populated by literal assignment in each layer module, not by this
        hook, so leaving ``code`` unset here changes nothing about them. A
        subclass that declines can still be registered later, on demand, via
        the owning class's :meth:`register` classmethod or the matching
        ``register_*`` helper in :mod:`pcapkit.foundation.registry.protocols`.

        ``code`` accepts:

        * a single enum member, whose *type* determines the destination
          registry (or registries) -- e.g. any
          :class:`~pcapkit.const.reg.ethertype.EtherType` member always means
          :class:`~pcapkit.protocols.link.link.Link`, and any
          :class:`~pcapkit.const.reg.linktype.LinkType` member means *both*
          :class:`~pcapkit.protocols.misc.pcap.frame.Frame` **and**
          :class:`~pcapkit.protocols.misc.pcapng.PCAPNG`;
        * a :class:`dict` mapping a destination class to a key, for a key
          that cannot name its own destination -- a raw :class:`int` port,
          for instance, is ambiguous between
          :class:`~pcapkit.protocols.transport.tcp.TCP` and
          :class:`~pcapkit.protocols.transport.udp.UDP`, and *must* use this
          form;
        * an iterable mixing either of the above, to register the same class
          into several registries from a single declaration -- e.g. a
          :class:`~pcapkit.protocols.link.l2tp.L2TP` subclass reachable both
          by its IP protocol number and by a UDP port.

        The explicit mapping form is accepted even for a key whose type could
        be inferred: being more explicit than required is never an error.

        Inference refuses rather than guesses: an enum member whose type
        names no known destination raises
        :exc:`~pcapkit.utilities.exceptions.RegistryError` instead of
        silently doing nothing or picking an arbitrary registry.

        See Also:
            :func:`pcapkit.foundation.registry.protocols.register_protocol_code`
            implements the resolution described above.

        """
        if args or kwargs:
            unexpected = ', '.join([*map(repr, args), *sorted(kwargs)])
            raise UnsupportedCall(f'{cls.__name__}: unexpected class keyword(s): {unexpected}')

        super().__init_subclass__()

        if schema is None:
            schema = cast('Type[_ST]', getattr(schema_module, cls.__name__, Schema_Raw))
        if data is None:
            data = cast('Type[_PT]', getattr(data_module, cls.__name__, Data_Raw))

        cls.__schema__ = schema
        cls.__data__ = data

        if code is not None:
            from pcapkit.foundation.registry.protocols import \
                register_protocol_code  # pylint: disable=import-outside-toplevel

            register_protocol_code(cls, code)

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

            So a miss resolves its fallback descriptor again on every frame, and
            what keeps that affordable is :attr:`ModuleDescriptor.klass
            <pcapkit.corekit.module.ModuleDescriptor.klass>` reading
            :data:`sys.modules` instead of re-entering
            :func:`importlib.import_module` -- see #574. Memoising the resolved
            class here instead, whether under ``proto``, in ``registry``'s
            default factory, or in a cache beside the registry, would retain a
            class that :func:`importlib.reload` then makes stale; #425 and #428
            at this layer and #560 at the schema layer are all that same defect.

        """
        protocol = ProtocolBase._lookup_registry(registry, proto)
        if isinstance(protocol, ModuleDescriptor):
            klass = protocol.klass
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
            from pcapkit.protocols.misc.null import NoPayload as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.misc.raw import Raw as protocol  # isort: skip # pylint: disable=import-outside-toplevel
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
                          data: 'Optional[Type[_PT]]' = None,
                          code: 'Any' = None,
                          *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialisation for subclasses.

        Args:
            schema: Schema class.
            data: Data class.
            code: Next-layer dispatch registration key(s). :data:`None` (the
                default) skips registration entirely. See
                :meth:`ProtocolBase.__init_subclass__` for the accepted
                shapes and the enum-type inference rule.
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
            :class:`~pcapkit.protocols.schema.misc.raw.Raw` and
            :class:`~pcapkit.protocols.data.misc.raw.Raw` classes will be used.

        This method also registers the subclass to the protocol registry,
        i.e., :attr:`pcapkit.protocols.__proto__`. That registration is
        unconditional -- it is the name-keyed identity registry, unrelated to
        the ``code`` keyword -- whereas ``code``'s next-layer dispatch
        registration is opt-in; see
        :meth:`ProtocolBase.__init_subclass__` for the latter.

        See Also:
            For more information on the registry, please refer to
            :func:`pcapkit.foundation.registry.protocols.register_protocol`.

        """
        from pcapkit.foundation.registry.protocols import register_protocol
        register_protocol(cls)

        return super().__init_subclass__(schema, data, code, *args, **kwargs)
