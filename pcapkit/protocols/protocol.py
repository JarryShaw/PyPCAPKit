# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""Root Protocol
===================

.. module:: pcapkit.protocols.protocol

:mod:`pcapkit.protocols.protocol` contains
:class:`~pcapkit.protocols.protocol.Protocol`, the abstract base class for a
new protocol stack, and :class:`~pcapkit.protocols.protocol.ProtocolBase`,
from which the built-in protocol families derive, with its metaclass
:class:`~pcapkit.protocols.protocol.ProtocolMeta`.

.. versionchanged:: 1.5.0

   Constructing a protocol with a keyword that none of its signatures
   declares raises :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`,
   where it was discarded (:issue:`617`). A next layer captured shorter than
   its header is kept as :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, where it
   was parsed with zero-filled fields (:issue:`1170`).

"""
import abc
import collections
import collections.abc
import contextlib
import contextvars
import copy
import difflib
import enum
import functools
import importlib
import inspect
import io
import os
import shutil
import string
import struct
import textwrap
import traceback
import types
import urllib.parse
from typing import TYPE_CHECKING, Any, Generic, Optional, Type, TypeVar, cast, overload

import aenum

from pcapkit.corekit.context import ContextRegistry
from pcapkit.corekit.decorators import beholder, seekset
from pcapkit.corekit.fields.misc import ConditionalField, SchemaField, SwitchField
from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.multidict import MultiDict
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.corekit.sentinels import ABSENT, NO_VALUE, NoValueType
from pcapkit.protocols.data import Data
from pcapkit.protocols.data import Packet as Data_Packet
from pcapkit.protocols.schema import Schema
from pcapkit.utilities import config
from pcapkit.utilities.chardet import detect
from pcapkit.utilities.compat import cached_property
from pcapkit.utilities.contextvars import beholding, frame_depth, rebuilding
from pcapkit.utilities.exceptions import (BaseError, CaughtByCaller, FormatError, ProtocolError,
                                          ProtocolNotFound, ProtocolNotImplemented, RegistryError,
                                          StructError, UnexpectedKeyword, UnsupportedCall,
                                          stacklevel)
from pcapkit.utilities.inspect import isabstract
from pcapkit.utilities.logging import DEVMODE, VERBOSE, get_logger
from pcapkit.utilities.warnings import (ProtocolWarning, RegistryWarning, UnknownFieldWarning,
                                        hold_warnings, warn)

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from types import FrameType
    from typing import IO, Any, Callable, DefaultDict, Iterable, Mapping, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal, Self

    from pcapkit.corekit.context import ProtocolContext
    from pcapkit.corekit.enum import EnumLookup

__all__ = ['Protocol', 'ProtocolBase']

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)

_PT = TypeVar('_PT', bound='Data')
_ST = TypeVar('_ST', bound='Schema')
_CTX = TypeVar('_CTX', bound='ProtocolContext')
_VT = TypeVar('_VT')
_ET = TypeVar('_ET', bound='EnumLookup')

# readable characters' order list
readable = [ord(char) for char in filter(lambda char: not char.isspace(), string.printable)]


def _passes_raw(value: 'Any', nested: 'bool' = False) -> 'bool':
    """Tell if ``make()`` keywords may carry a raw :obj:`bytes` item.

    Args:
        value: keyword arguments of ``make()``, or a value within them
        nested: if ``value`` sits inside a container

    Returns:
        :data:`True` if :obj:`bytes` sits anywhere inside a :obj:`list`,
        :obj:`tuple`, :obj:`dict` or data model among ``value``, or a
        :class:`~pcapkit.protocols.schema.Schema` does anywhere. A
        top-level :obj:`bytes` keyword (e.g. a payload) does not count. A data
        model is looked into as a :obj:`dict` is, since a maker builds from its
        fields as given, and a multi-mapping through every value of each key
        (:issue:`2725`).

    """
    if isinstance(value, bytes):
        return nested
    if isinstance(value, Schema):  # a ready-made item, which ``make()`` may pack into raw octets
        return True
    if isinstance(value, (Info, MultiDict)):
        return any(_passes_raw(item, nested) for key, item in value.items(multi=True) if key != '__packet__')
    if isinstance(value, dict):
        return any(_passes_raw(item, nested) for key, item in value.items() if key != '__packet__')
    if isinstance(value, (list, tuple)):
        return any(_passes_raw(item, True) for item in value)
    return False


@functools.lru_cache(maxsize=None)
def _schema_slots(schema: 'Type[Schema]') -> 'tuple[str, ...]':
    """Names of the fields of ``schema`` that hold a schema.

    Args:
        schema: schema class

    Returns:
        Names of the :class:`~pcapkit.corekit.fields.misc.SchemaField` and
        :class:`~pcapkit.corekit.fields.misc.SwitchField` fields, including
        those wrapped in a :class:`~pcapkit.corekit.fields.misc.ConditionalField`.

    """
    slots = []
    for name, field in schema.__fields__.items():
        while isinstance(field, ConditionalField):
            field = field.field
        if isinstance(field, (SchemaField, SwitchField)):
            slots.append(name)
    return tuple(slots)


def _holds_raw(value: 'Any') -> 'bool':
    """Tell if a made schema may hold raw :obj:`bytes` in place of a schema.

    Args:
        value: made schema, or a value within it

    Returns:
        :data:`True` if ``value`` holds :obj:`bytes` as a list item, or as
        the value of a field that holds a schema
        (:class:`~pcapkit.corekit.fields.misc.SchemaField` or
        :class:`~pcapkit.corekit.fields.misc.SwitchField`).

    """
    if isinstance(value, (list, tuple)):
        return any(isinstance(item, bytes) or _holds_raw(item) for item in value)
    if isinstance(value, Schema):
        for name, field in value.__fields__.items():
            item = value.get(name)
            while isinstance(field, ConditionalField):
                field = field.field
            if isinstance(item, bytes) and isinstance(field, (SchemaField, SwitchField)):
                return True
            if _holds_raw(item):
                return True
    return False


def _raw_where_parsed(made: 'Any', parsed: 'Any') -> 'bool':
    """Tell if ``made`` holds raw :obj:`bytes` where ``parsed`` holds a schema.

    Args:
        made: made schema, or a value within it
        parsed: the same position in the schema parsed from its packed octets

    Returns:
        :data:`True` if, at some position both share, ``made`` holds
        :obj:`bytes` and ``parsed`` a :class:`~pcapkit.protocols.schema.Schema`.

    """
    if isinstance(made, bytes):
        return isinstance(parsed, Schema)
    if isinstance(made, (list, tuple)) and isinstance(parsed, (list, tuple)):
        return any(_raw_where_parsed(item, other) for item, other in zip(made, parsed))
    if isinstance(made, Schema) and isinstance(parsed, Schema):
        return any(_raw_where_parsed(made.get(name), parsed.get(name))
                   for name in made.__fields__ if name in parsed.__fields__)
    return False

#: The layers a parse may stop at, as ``layer`` names them, case-insensitively
#: (:issue:`2840`).
_LAYERS = ('link', 'internet', 'transport', 'application')

#: The state a layer hands the layer it carries, through
#: :meth:`ProtocolBase._from_parent <pcapkit.protocols.protocol.ProtocolBase._from_parent>`
#: rather than the public constructor (:issue:`2840`). It reaches
#: :meth:`Protocol.__post_init__ <pcapkit.protocols.protocol.Protocol.__post_init__>`, and
#: the hooks after it, as keywords:
#:
#: * ``alias``, the code the layer was dispatched on, and ``error``, the failure a
#:   layer kept as :class:`~pcapkit.protocols.misc.raw.protocol.Raw` records;
#: * ``packet``, the enclosing layer's packet data, and ``__packet__``, the copy of it
#:   a re-dispatch of the same octets shares, as TLS's SSLv2 trial does;
#: * ``version``, the enclosing IP version, ``extension``, whether the layer is an IPv6
#:   extension header, and ``_exthdr_depth``, its place in a chain of them;
#: * ``framed``, whether a DNS message carries the two-octet TCP length, and
#:   ``chained``, whether a TLS record follows another in its segment.
_NEXT_LAYER_KEYWORDS = frozenset({'alias', 'error', 'packet', '__packet__', 'version',
                                  'extension', '_exthdr_depth', 'framed', 'chained'})

#: contextvars.ContextVar[dict[str, Any] | None]: The next-layer state
#: :meth:`ProtocolBase._analyze_from_parent
#: <pcapkit.protocols.protocol.ProtocolBase._analyze_from_parent>` hands the
#: :meth:`~pcapkit.protocols.protocol.ProtocolBase.analyze` it calls, whose
#: :meth:`~pcapkit.protocols.protocol.ProtocolBase._analyze_next_layer` takes it for
#: that payload alone, as :meth:`~pcapkit.protocols.protocol.ProtocolBase._from_parent`
#: hands :meth:`~pcapkit.protocols.protocol.ProtocolBase.__init__` its state on
#: :attr:`~pcapkit.protocols.protocol.ProtocolBase.__next_layer__` (:issue:`2840`).
_analyze_state = contextvars.ContextVar(
    'pcapkit.protocols.protocol._analyze_state', default=None,
)  # type: contextvars.ContextVar[Optional[dict[str, Any]]]


#: Cache for :func:`_declared_keywords`, keyed by protocol class. Signatures do
#: not change after the class is created and the walk below is
#: :math:`O(\\text{MRO} \\times \\text{methods})`, so it runs once per class
#: rather than once per constructed packet.
_DECLARED_KEYWORDS = {}  # type: dict[type, Optional[frozenset[str]]]

#: Methods a construction keyword may be for.
#: :meth:`Protocol.__post_init__ <pcapkit.protocols.protocol.Protocol.__post_init__>`
#: passes the same ``**kwargs`` to :meth:`pack <pcapkit.protocols.protocol.Protocol.pack>`
#: (and so ``make``) *and* :meth:`unpack <pcapkit.protocols.protocol.Protocol.unpack>`
#: (and so ``read``).
#:
#: .. versionchanged:: 1.8.0
#:
#:    ``__init__`` is not among them, so its parameters are no construction keywords
#:    (:issue:`2840`).
_KEYWORD_CONSUMERS = ('make', 'read', 'pack', 'unpack', '__post_init__')

#: The names a parse gives the octets and their length, positional-only on
#: :meth:`Protocol.__init__ <pcapkit.protocols.protocol.Protocol.__init__>` and
#: the first parameters of the hooks. A keyword of either name is a field, which
#: a construction hands :meth:`Protocol.pack <pcapkit.protocols.protocol.Protocol.pack>`
#: on :attr:`~pcapkit.protocols.protocol.ProtocolBase.__named_fields__` past the
#: hooks that would take it for theirs (:issue:`3081`).
_PARSE_NAMES = ('file', 'length')


def _declared_keywords(cls: 'type') -> 'Optional[frozenset[str]]':
    """Collect every keyword the protocol ``cls`` declares a parameter for.

    Args:
        cls: Protocol class to inspect.

    Returns:
        Names of every keyword-acceptable parameter declared by any of
        :data:`_KEYWORD_CONSUMERS` anywhere in the MRO of ``cls``, but the
        hooks' own ``file`` and ``length``, plus every entry of :attr:`Protocol.__keywords__
        <pcapkit.protocols.protocol.Protocol.__keywords__>` found there.
        :obj:`None` if ``cls`` *itself* sets ``__keywords__`` to :obj:`None`,
        meaning its keywords cannot be enumerated and are not to be checked --
        inherited :obj:`None` does not count, as :attr:`Protocol.__keywords__
        <pcapkit.protocols.protocol.Protocol.__keywords__>` explains.

    The union is wider than the signature of ``cls.make``:
    :meth:`Protocol.__post_init__
    <pcapkit.protocols.protocol.Protocol.__post_init__>` hands one ``**kwargs``
    to both the construction and the parse, so a keyword ``read`` declares
    travels through ``make`` too, as ``extension`` of :meth:`HIP.read
    <pcapkit.protocols.internet.hip.protocol.HIP.read>` does.

    The walk covers the whole MRO, not the most derived override of each method,
    so a subclass forwarding to its parent keeps the parent's keywords. The
    exception is a class that sets :attr:`Protocol.__own_make_keywords__
    <pcapkit.protocols.protocol.Protocol.__own_make_keywords__>`: its ``make``
    counts only while no subclass overrides it (:issue:`2286`).

    .. versionchanged:: 1.8.0

       The hooks' ``file`` and ``length`` are left out, being what a parse is
       given, and ``OUT_OF_BAND_KEYWORDS`` is not added (:issue:`2840`); a
       ``make`` field of either name counts, as any field does (:issue:`3081`).

    """
    try:
        return _DECLARED_KEYWORDS[cls]
    except KeyError:
        pass

    unchecked = False
    names = set()  # type: set[str]
    # NOTE: The class whose ``make`` is the one ``cls`` resolves to; any other
    # ``make`` in the MRO has been overridden.
    make_owner = next((klass for klass in cls.__mro__ if 'make' in klass.__dict__), None)
    for klass in cls.__mro__:
        # NOTE: ``inspect.signature`` misses a keyword read out of ``**kwargs``,
        # so each class lists its own in ``__keywords__``, unioned down the MRO.
        keywords = klass.__dict__.get('__keywords__', ABSENT)
        if keywords is None:
            # NOTE: Not inherited: HTTP forwards to HTTPv1 or HTTPv2, which each
            # declare their keywords in full and so stay checked.
            if klass is cls:
                unchecked = True
        elif keywords is not ABSENT:
            names.update(keywords)

        for method in _KEYWORD_CONSUMERS:
            # NOTE: From ``__dict__``, not ``getattr``, so each class in the MRO
            # contributes its own definition, not the most derived one.
            func = klass.__dict__.get(method)
            if func is None:
                continue

            # NOTE: Read only while it is the ``make`` that ``cls`` uses; from
            # ``__dict__`` so the marker is not inherited.
            if (method == 'make' and klass is not make_owner
                    and klass.__dict__.get('__own_make_keywords__', False)):
                continue

            try:
                signature = inspect.signature(func)
            except (TypeError, ValueError):  # pragma: no cover
                # NOTE: Skipped, not fatal; the worst case is a false rejection.
                continue

            for name, param in signature.parameters.items():
                if name in ('self', 'cls'):
                    continue
                # NOTE: What a parse is given, which ``__post_init__`` and ``read`` declare;
                # a ``make`` field of the name is a field all the same (#3081).
                if method != 'make' and name in _PARSE_NAMES:
                    continue
                if param.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD,
                                  inspect.Parameter.KEYWORD_ONLY):
                    names.add(name)

    declared = None if unchecked else frozenset(names)
    _DECLARED_KEYWORDS[cls] = declared
    return declared


def _check_construction_keywords(cls: 'type', kwargs: 'Mapping[str, Any]', /, *,
                                 strict: 'bool' = True) -> 'None':
    """Reject construction keywords that the protocol ``cls`` declares nowhere.

    Args:
        cls: Protocol class being constructed.
        kwargs: Construction keywords to check: the fields
            :meth:`Protocol.from_fields
            <pcapkit.protocols.protocol.Protocol.from_fields>` is given, or the
            caller's own keywords of :meth:`Protocol.from_data
            <pcapkit.protocols.protocol.Protocol.from_data>` and then those with
            :meth:`Protocol._make_data
            <pcapkit.protocols.protocol.Protocol._make_data>`'s added.
        strict: Whether an unexpected keyword is an error. :data:`True` for a
            caller's own construction; :data:`False` when the keywords were
            generated by :meth:`Protocol._make_data
            <pcapkit.protocols.protocol.Protocol._make_data>` rather than
            written by anybody -- see :meth:`Protocol.from_data
            <pcapkit.protocols.protocol.Protocol.from_data>`.

    Raises:
        UnexpectedKeyword: If ``strict`` and any keyword is not among those
            :func:`_declared_keywords` collects for ``cls``.

    Warns:
        UnknownFieldWarning: The same finding when not ``strict``.

    .. versionchanged:: 1.8.0

       ``cls`` and ``kwargs`` are positional-only and ``strict`` keyword-only,
       and the error is :exc:`~pcapkit.utilities.exceptions.UnexpectedKeyword`,
       an :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` that is a
       :exc:`TypeError` too (:issue:`2840`).

    """
    declared = _declared_keywords(cls)
    if declared is None:
        return

    unexpected = sorted(key for key in kwargs if key not in declared)
    if not unexpected:
        return

    # NOTE: The check catches misspellings, so suggest the closest accepted name, e.g. ``seq_no``
    # for ``seq``; ``from_fields`` and ``from_data`` take ``context`` too.
    candidates = declared | {'context'}
    report = []  # type: list[str]
    for key in unexpected:
        suggestions = difflib.get_close_matches(key, candidates, n=1)
        report.append(f'{key!r} (did you mean {suggestions[0]!r}?)' if suggestions else repr(key))
    listed = ', '.join(report)

    if strict:
        # NOTE: A keyword is never the positional of its name, so say how to parse (#3081).
        hint = ('; to parse, pass the file and its length positionally'
                if any(key in _PARSE_NAMES for key in unexpected) else '')
        raise UnexpectedKeyword(f'{cls.__name__}: unexpected keyword(s): {listed}{hint}')

    # NOTE: A warning, not an error: the caller cannot fix keys ``_make_data`` generated, and
    # raising would break ``from_data``; the default ``stacklevel`` blames that call.
    warn(f'{cls.__name__}._make_data returned keyword(s) that no signature of '
         f'{cls.__name__} declares, so they are discarded: {listed}',
         UnknownFieldWarning)


def _nothing_to_parse(cls: 'type') -> 'TypeError':
    """The error a parse given no octets raises.

    Args:
        cls: Protocol class being parsed.

    Returns:
        A :exc:`TypeError` naming ``cls`` and :meth:`Protocol.from_fields
        <pcapkit.protocols.protocol.Protocol.from_fields>`, which builds one
        instead (:issue:`2840`).

    .. versionadded:: 1.8.0

    """
    name = cls.__name__
    return TypeError(f'{name}: nothing to parse; build one with {name}.from_fields()')


def _fields_with_a_file(cls: 'type', fields: 'Mapping[str, Any]') -> 'TypeError':
    """The error a parse given keywords besides its own raises.

    Args:
        cls: Protocol class being parsed.
        fields: The keywords besides those the parse of ``cls`` takes.

    Returns:
        A :exc:`TypeError` naming ``cls`` and each of ``fields`` (:issue:`3081`).

    .. versionadded:: 1.8.0

    """
    noun = 'argument' if len(fields) == 1 else 'arguments'
    listed = ', '.join(map(repr, sorted(fields)))
    return TypeError(f'{cls.__name__}: unexpected keyword {noun} {listed} for a parse')


def _named_fields(fields: 'dict[str, Any]') -> 'dict[str, Any]':
    """Take the fields named as the parse's file and length out of ``fields``.

    Args:
        fields: Construction keywords, updated in place.

    Returns:
        Those of ``fields`` keyed by :data:`_PARSE_NAMES`, for
        :attr:`ProtocolBase.__named_fields__` (:issue:`3081`).

    .. versionadded:: 1.8.0

    """
    return {name: fields.pop(name) for name in _PARSE_NAMES if name in fields}


def _stops_without_a_file(cls: 'type', names: 'Iterable[str]') -> 'TypeError':
    """The error a construction given a stop or a length raises.

    Args:
        cls: Protocol class being constructed.
        names: The parameters given that only bound a parse.

    Returns:
        A :exc:`TypeError` naming ``cls`` and each of ``names``, since a
        construction takes no stop (:issue:`2840`, :issue:`3081`).

    .. versionadded:: 1.8.0

    """
    listed = ', '.join(map(repr, names))
    return TypeError(f'{cls.__name__}: no file to parse, so no {listed}')


def _short_of_hint(klass: 'Type[ProtocolBase]', captured: 'int') -> 'bool':
    """Tell whether ``captured`` octets may be too few for a ``klass`` header.

    Args:
        klass: Next layer protocol class.
        captured: Octets captured for it.

    Returns:
        Whether a next layer of ``klass`` parsed from ``captured`` octets may be
        replaced with :class:`~pcapkit.protocols.misc.raw.protocol.Raw` by
        :meth:`Protocol._parse_next_layer
        <pcapkit.protocols.protocol.Protocol._parse_next_layer>`, and so has
        its warnings held.

    The hint is read from the class, before there is an instance to ask, which
    is enough for every protocol shipped: each returns a constant. A hint that
    needs an instance raises here instead, and the layer counts as short, which
    only means its warnings are held until the parse is known to be kept.

    """
    try:
        hint = klass.__length_hint__(cast('ProtocolBase', None))
    except Exception:  # pylint: disable=broad-except
        return True
    return hint is not None and captured < hint


def _sibling_model(cls: 'Type[ProtocolBase]', role: 'str') -> 'Any':
    """The ``role`` class for a protocol class defined without one (:issue:`2534`).

    Args:
        cls: The protocol class being defined.
        role: ``'schema'`` or ``'data'``, the module to look in.

    Returns:
        The class named after ``cls`` in the ``role`` module of the package whose
        ``protocol`` module defines ``cls``, if there is one; otherwise
        :class:`~pcapkit.protocols.misc.raw.schema.Raw` or
        :class:`~pcapkit.protocols.misc.raw.data.Raw`.

    """
    package, _, name = cls.__module__.rpartition('.')
    if name == 'protocol' and package != __name__.rpartition('.')[0]:
        sibling = f'{package}.{role}'
        try:
            module = importlib.import_module(sibling)
        except ModuleNotFoundError as exc:
            if exc.name != sibling:
                raise
        else:
            found = getattr(module, cls.__name__, None)
            if isinstance(found, type):
                return found
    # NOTE: imported here rather than at the top: Raw's package is under
    # pcapkit.protocols.misc, whose modules import this one (#2534).
    if role == 'schema':
        from pcapkit.protocols.misc.raw.schema import \
            Raw as Schema_Raw  # pylint: disable=import-outside-toplevel
        return Schema_Raw
    from pcapkit.protocols.misc.raw.data import \
        Raw as Data_Raw  # pylint: disable=import-outside-toplevel
    return Data_Raw


class ProtocolMeta(abc.ABCMeta):
    """Metaclass of :class:`ProtocolBase`, and so of every protocol class.

    Over :class:`abc.ABCMeta`, it adds the class property :attr:`registry`.

    """

    @property
    def registry(cls) -> 'types.MappingProxyType[str, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]':
        """Read-only view of the by-name protocol registry.

        It is :attr:`ProtocolBase.__registry__`, with each entry as stored: a
        built-in protocol is the :class:`~pcapkit.corekit.module.ModuleDescriptor`
        naming it, so reading the view imports nothing. Look a class up with
        :meth:`ProtocolBase.get_protocol`, which resolves a descriptor.

        Note:
            Every protocol class reads the same map, later registrations
            included. Defined on the metaclass, it is a class attribute, **not**
            an instance one.

        .. versionadded:: 1.6.0

        """
        return types.MappingProxyType(ProtocolBase.__registry__)


class ProtocolBase(Generic[_PT, _ST], metaclass=ProtocolMeta):
    """Abstract base class for all protocol families.

    The built-in protocol families -- the layer base classes
    :class:`~pcapkit.protocols.link.link.Link`,
    :class:`~pcapkit.protocols.internet.internet.Internet`,
    :class:`~pcapkit.protocols.transport.transport.Transport` and
    :class:`~pcapkit.protocols.application.application.Application`, and the
    miscellaneous protocols in :mod:`pcapkit.protocols.misc`, PCAP and PCAP-NG
    included -- derive from this class directly. Its metaclass is
    :class:`ProtocolMeta`.

    Note:
        This class is for internal use only. For customisation, subclass
        :class:`Protocol` to create a new protocol stack, or the matching
        layer base class above for a new protocol in an existing layer.

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
        #: If a header set before :meth:`unpack` may hold raw items.
        _make_raw: 'bool'
        #: File pointer.
        _seekset: 'int'
        #: Parse packet until such layer.
        _exlayer: 'Optional[str]'
        #: Parse packet until such protocol.
        _exproto: 'Optional[str | ProtocolBase | Type[ProtocolBase]]'
        #: Whether to stop parsing the next layer of protocol.
        _sigterm: 'bool'

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
    #: :class:`~pcapkit.protocols.link.ethernet.protocol.Ethernet` is ``Link``. However,
    #: certain protocols are not in any layer, such as
    #: :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, and thus its layer is :obj:`None`.
    __layer__: 'Optional[Literal["Link", "Internet", "Transport", "Application"]]' = None

    #: Protocol index mapping for decoding the next layer; see
    #: :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: and :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    #: Each value is a :class:`~pcapkit.corekit.module.ModuleDescriptor` naming the
    #: module and class, or a :class:`ProtocolBase` subclass.
    __proto__: 'DefaultDict[int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]' = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw.protocol', 'Raw'),
    )

    #: Read-only copy of :attr:`__proto__` as the class defining it shipped it,
    #: taken by :meth:`__init_subclass__` before anything can register into it.
    #: :meth:`_next_layer_entry` reads it to tell a descriptor handed back from
    #: a new one without resolving it (:issue:`1504`).
    _shipped_proto: 'types.MappingProxyType[Any, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]' = \
        types.MappingProxyType({})

    #: Protocol registry by name, holding each protocol class under its
    #: upper-cased class name, ``'IPV4'`` for :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`.
    #: Each built-in protocol is a :class:`~pcapkit.corekit.module.ModuleDescriptor`
    #: here, so the map names every one before any is imported, and
    #: :meth:`get_protocol` imports a class only when it resolves its entry
    #: (:issue:`2763`). :meth:`Protocol.__init_subclass__` adds each concrete
    #: :class:`Protocol` subclass as it is defined, :meth:`register_protocol`
    #: replaces an entry, and :attr:`ProtocolMeta.registry` is a read-only view.
    #:
    #: .. versionadded:: 1.6.0
    __registry__: 'dict[str, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]' = {
        # Link Layer
        'ARP': ModuleDescriptor('pcapkit.protocols.link.arp.protocol', 'ARP'),
        'C_TAG': ModuleDescriptor('pcapkit.protocols.link.c_tag.protocol', 'C_Tag'),
        'ETHERNET': ModuleDescriptor('pcapkit.protocols.link.ethernet.protocol', 'Ethernet'),
        'FRAD': ModuleDescriptor('pcapkit.protocols.link.frad.protocol', 'FRAD'),
        'GRE': ModuleDescriptor('pcapkit.protocols.link.gre.protocol', 'GRE'),
        'IEEE802_11': ModuleDescriptor('pcapkit.protocols.link.ieee802_11.protocol', 'IEEE802_11'),
        'INARP': ModuleDescriptor('pcapkit.protocols.link.inarp.protocol', 'InARP'),
        'L2TP': ModuleDescriptor('pcapkit.protocols.link.l2tp.protocol', 'L2TP'),
        'L2TPV2': ModuleDescriptor('pcapkit.protocols.link.l2tpv2.protocol', 'L2TPv2'),
        'LINUXSLL': ModuleDescriptor('pcapkit.protocols.link.linux_sll.protocol', 'LinuxSLL'),
        'LINUXSLL1': ModuleDescriptor('pcapkit.protocols.link.linux_sll1.protocol', 'LinuxSLL1'),
        'LINUXSLL2': ModuleDescriptor('pcapkit.protocols.link.linux_sll2.protocol', 'LinuxSLL2'),
        'LLC': ModuleDescriptor('pcapkit.protocols.link.llc.protocol', 'LLC'),
        'LOOPBACK': ModuleDescriptor('pcapkit.protocols.link.loopback.protocol', 'Loopback'),
        'NETLINK': ModuleDescriptor('pcapkit.protocols.link.netlink.protocol', 'Netlink'),
        'PPP': ModuleDescriptor('pcapkit.protocols.link.ppp.protocol', 'PPP'),
        'PPPOE': ModuleDescriptor('pcapkit.protocols.link.pppoe.protocol', 'PPPoE'),
        'RADIOTAP': ModuleDescriptor('pcapkit.protocols.link.radiotap.protocol', 'Radiotap'),
        'SNAP': ModuleDescriptor('pcapkit.protocols.link.snap.protocol', 'SNAP'),
        'S_TAG': ModuleDescriptor('pcapkit.protocols.link.s_tag.protocol', 'S_Tag'),
        'VLAN': ModuleDescriptor('pcapkit.protocols.link.vlan.protocol', 'VLAN'),
        # Internet Layer
        'AH': ModuleDescriptor('pcapkit.protocols.internet.ah.protocol', 'AH'),
        'ESP': ModuleDescriptor('pcapkit.protocols.internet.esp.protocol', 'ESP'),
        'HIP': ModuleDescriptor('pcapkit.protocols.internet.hip.protocol', 'HIP'),
        'HOPOPT': ModuleDescriptor('pcapkit.protocols.internet.hopopt.protocol', 'HOPOPT'),
        'ICMP': ModuleDescriptor('pcapkit.protocols.internet.icmp.protocol', 'ICMP'),
        'ICMPV4': ModuleDescriptor('pcapkit.protocols.internet.icmpv4.protocol', 'ICMPv4'),
        'ICMPV6': ModuleDescriptor('pcapkit.protocols.internet.icmpv6.protocol', 'ICMPv6'),
        'IGMP': ModuleDescriptor('pcapkit.protocols.internet.igmp.protocol', 'IGMP'),
        'IGMPV1': ModuleDescriptor('pcapkit.protocols.internet.igmpv1.protocol', 'IGMPv1'),
        'IGMPV2': ModuleDescriptor('pcapkit.protocols.internet.igmpv2.protocol', 'IGMPv2'),
        'IGMPV3': ModuleDescriptor('pcapkit.protocols.internet.igmpv3.protocol', 'IGMPv3'),
        'IP': ModuleDescriptor('pcapkit.protocols.internet.ip.protocol', 'IP'),
        'IPSEC': ModuleDescriptor('pcapkit.protocols.internet.ipsec.protocol', 'IPsec'),
        'IPV4': ModuleDescriptor('pcapkit.protocols.internet.ipv4.protocol', 'IPv4'),
        'IPV6': ModuleDescriptor('pcapkit.protocols.internet.ipv6.protocol', 'IPv6'),
        'IPV6_EXT': ModuleDescriptor('pcapkit.protocols.internet.ipv6_ext.protocol', 'IPv6_Ext'),
        'IPV6_FRAG': ModuleDescriptor('pcapkit.protocols.internet.ipv6_frag.protocol', 'IPv6_Frag'),
        'IPV6_OPTS': ModuleDescriptor('pcapkit.protocols.internet.ipv6_opts.protocol', 'IPv6_Opts'),
        'IPV6_ROUTE': ModuleDescriptor('pcapkit.protocols.internet.ipv6_route.protocol', 'IPv6_Route'),
        'IPX': ModuleDescriptor('pcapkit.protocols.internet.ipx.protocol', 'IPX'),
        'MH': ModuleDescriptor('pcapkit.protocols.internet.mh.protocol', 'MH'),
        # Transport Layer
        'DCCP': ModuleDescriptor('pcapkit.protocols.transport.dccp.protocol', 'DCCP'),
        'SCTP': ModuleDescriptor('pcapkit.protocols.transport.sctp.protocol', 'SCTP'),
        'TCP': ModuleDescriptor('pcapkit.protocols.transport.tcp.protocol', 'TCP'),
        'UDP': ModuleDescriptor('pcapkit.protocols.transport.udp.protocol', 'UDP'),
        # Application Layer
        'DNS': ModuleDescriptor('pcapkit.protocols.application.dns.protocol', 'DNS'),
        'DRARP': ModuleDescriptor('pcapkit.protocols.application.drarp.protocol', 'DRARP'),
        'DTLS': ModuleDescriptor('pcapkit.protocols.application.dtls.protocol', 'DTLS'),
        'FTP': ModuleDescriptor('pcapkit.protocols.application.ftp.protocol', 'FTP'),
        'FTP_DATA': ModuleDescriptor('pcapkit.protocols.application.ftp_data.protocol', 'FTP_DATA'),
        'HTTP': ModuleDescriptor('pcapkit.protocols.application.http.protocol', 'HTTP'),
        'HTTPV1': ModuleDescriptor('pcapkit.protocols.application.httpv1.protocol', 'HTTPv1'),
        'HTTPV2': ModuleDescriptor('pcapkit.protocols.application.httpv2.protocol', 'HTTPv2'),
        'MSTP': ModuleDescriptor('pcapkit.protocols.application.mstp.protocol', 'MSTP'),
        'NGAP': ModuleDescriptor('pcapkit.protocols.application.ngap.protocol', 'NGAP'),
        'OSPF': ModuleDescriptor('pcapkit.protocols.application.ospf.protocol', 'OSPF'),
        'OSPFV1': ModuleDescriptor('pcapkit.protocols.application.ospfv1.protocol', 'OSPFv1'),
        'OSPFV2': ModuleDescriptor('pcapkit.protocols.application.ospfv2.protocol', 'OSPFv2'),
        'OSPFV3': ModuleDescriptor('pcapkit.protocols.application.ospfv3.protocol', 'OSPFv3'),
        'RARP': ModuleDescriptor('pcapkit.protocols.application.rarp.protocol', 'RARP'),
        'RSTP': ModuleDescriptor('pcapkit.protocols.application.rstp.protocol', 'RSTP'),
        'SSL': ModuleDescriptor('pcapkit.protocols.application.ssl.protocol', 'SSL'),
        'SSLV2': ModuleDescriptor('pcapkit.protocols.application.sslv2.protocol', 'SSLv2'),
        'SSLV3': ModuleDescriptor('pcapkit.protocols.application.sslv3.protocol', 'SSLv3'),
        'STP': ModuleDescriptor('pcapkit.protocols.application.stp.protocol', 'STP'),
        'STPV0': ModuleDescriptor('pcapkit.protocols.application.stpv0.protocol', 'STPv0'),
        'TLS': ModuleDescriptor('pcapkit.protocols.application.tls.protocol', 'TLS'),
        # Miscellaneous
        'FRAME': ModuleDescriptor('pcapkit.protocols.misc.pcap.frame.protocol', 'Frame'),
        'HEADER': ModuleDescriptor('pcapkit.protocols.misc.pcap.header.protocol', 'Header'),
        'IP_PSEUDO': ModuleDescriptor('pcapkit.protocols.misc.checksum.ip_pseudo.protocol', 'IP_Pseudo'),
        'NOPAYLOAD': ModuleDescriptor('pcapkit.protocols.misc.no_payload.protocol', 'NoPayload'),
        'PCAPNG': ModuleDescriptor('pcapkit.protocols.misc.pcapng.protocol', 'PCAPNG'),
        'RAW': ModuleDescriptor('pcapkit.protocols.misc.raw.protocol', 'Raw'),
    }

    #: Read-only copy of :attr:`__registry__` as shipped, which
    #: :meth:`register_protocol` reads to put a built-in's descriptor back
    #: rather than its class, as :attr:`_shipped_proto` serves
    #: :meth:`register` (:issue:`1504`).
    _shipped_registry: 'types.MappingProxyType[str, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]' = \
        types.MappingProxyType(dict(__registry__))

    #: Construction keywords this protocol takes out of ``**kwargs`` by name
    #: rather than declaring as a parameter, as :meth:`IPv6_Ext.read
    #: <pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext.read>` does with
    #: ``alias``. :func:`_declared_keywords` reads signatures, which miss such a
    #: name, so the construction check of :meth:`from_fields` accepts only those
    #: listed here, unioned over the MRO. Prefer a declared parameter, which also
    #: documents the keyword (:issue:`617`). This class lists ``__packet__``,
    #: which :meth:`pack` reads for every protocol.
    #:
    #: :obj:`None` skips the check, for a *dispatcher* whose real signature is
    #: chosen at call time: :meth:`HTTP.make
    #: <pcapkit.protocols.application.http.protocol.HTTP.make>` declares only
    #: ``version`` and forwards the rest to :meth:`HTTPv1.make
    #: <pcapkit.protocols.application.httpv1.protocol.HTTPv1.make>` or
    #: :meth:`HTTPv2.make <pcapkit.protocols.application.httpv2.protocol.HTTPv2.make>`.
    #: A protocol that skips the check discards an unknown keyword silently.
    #: Unlike a set, :obj:`None` is **not** inherited, so ``HTTPv1`` and
    #: ``HTTPv2``, which declare their keywords in full, stay checked.
    #:
    #: .. versionchanged:: 1.8.0
    #:
    #:    This class lists ``__packet__`` (:issue:`2840`).
    __keywords__: 'Optional[frozenset[str]]' = frozenset({'__packet__'})

    #: Whether the parameters of this class's own :meth:`make` are accepted only
    #: while that ``make`` is the one in use. By default
    #: :func:`_declared_keywords` takes every ``make`` in the MRO. A base whose
    #: subclasses override ``make`` *without* forwarding sets this, so its
    #: keywords are refused for them rather than accepted and dropped, as
    #: :class:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext` does for
    #: ``len`` and ``data`` (:issue:`2286`). Not inherited, and
    #: :attr:`__keywords__` and the other construction methods are unaffected.
    __own_make_keywords__: 'bool' = False

    #: The ``__short_read__`` record of the data model :meth:`from_data`
    #: rebuilds this instance from. :meth:`pack` cuts the header it makes back
    #: to the octets captured, and :meth:`__post_init__` has :meth:`unpack`
    #: parse them at the width ``__short_width__`` records, so the rebuild is
    #: parsed as its capture was (:issue:`2703`, :issue:`2761`). Set for that
    #: call alone; otherwise :data:`None`.
    __short_read__: 'Optional[tuple[str, int]]' = None

    #: The next-layer state :meth:`_from_parent` hands this layer, keyed as
    #: :data:`~pcapkit.protocols.protocol._NEXT_LAYER_KEYWORDS`. :meth:`__init__`
    #: and :meth:`_parse` take it over the keywords they are given, so a default
    #: an override passes on cannot mask it. Set for that call alone, like
    #: :attr:`__short_read__`; otherwise :data:`None`.
    __next_layer__: 'Optional[dict[str, Any]]' = None

    #: The fields named as the parse's ``file`` and ``length``, which a
    #: construction hands :meth:`pack` past :meth:`__post_init__` and the hooks
    #: after it, whose own parameters those names are; :meth:`pack` takes them
    #: into the keywords for :meth:`make` (:issue:`3081`). Set for that call
    #: alone, like :attr:`__next_layer__`; otherwise :data:`None`.
    __named_fields__: 'Optional[dict[str, Any]]' = None

    #: Caller supplied parsing context; see :mod:`pcapkit.corekit.context`.
    #: :meth:`self.__init__ <Protocol.__init__>` sets a
    #: :class:`~pcapkit.corekit.context.ContextRegistry`; an instance built
    #: without ``__init__`` reads the class-level :data:`None`.
    _exctx: 'Optional[ContextRegistry]' = None

    #: Whether :meth:`_parse_next_layer` kept this layer as
    #: :class:`~pcapkit.protocols.misc.raw.protocol.Raw` unparsed, being past
    #: :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`. Such a layer carries
    #: an ``error`` as a failed parse does; this tells the two apart, for what
    #: follows the limit is not to be read on (:issue:`1610`).
    _past_layer_limit: 'bool' = False

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

    # key name for the data model
    @property
    def info_name(self) -> 'str':
        """Key the enclosing layer's :term:`data model` holds :attr:`info` under."""
        return self.__class__.__name__.lower()

    # data model of current instance
    @property
    def info(self) -> '_PT':
        """Parsed :term:`data model` of current instance."""
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
        """Protocol chain of current instance.

        Note:
            :class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload` has no chain and
            narrows this to :obj:`None`; :meth:`_decode_next_layer` passes it
            on as ``basis``, which
            :class:`~pcapkit.corekit.protochain.ProtoChain` accepts.

        """
        return self._protos

    # packet data
    @cached_property
    def packet(self) -> 'Data_Packet':
        """Packet data of the protocol.

        Note:
            The split takes :attr:`self.length <length>` as the length of the
            octets *preceding* the payload, and the payload as running to the
            end of the buffer: a header followed by its payload.

            A protocol laid out otherwise overrides this, or its header eats the
            payload and the payload is ``b''``.
            :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG` does: its
            :attr:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG.length` is the
            wire's Block Total Length, and the captured octets sit ahead of the
            option list and the trailing length field. The payload matters
            because :meth:`Protocol.__init__` injects it into every parsed
            ``_info``, which the dumpers write out.

        """
        try:
            return self._read_packet(header=self.length)
        except UnsupportedCall:
            return Data_Packet(
                header=b'',
                payload=self._read_packet(),
            )

    # header schema
    @cached_property
    def schema(self) -> '_ST':
        """Header :term:`schema` instance of the protocol."""
        return self.__header__

    # caller supplied parsing context
    @property
    def context(self) -> 'ContextRegistry':
        """Caller supplied parsing context.

        See Also:
            :mod:`pcapkit.corekit.context` for what this channel is for, and
            :meth:`self._get_context
            <pcapkit.protocols.protocol.Protocol._get_context>` for how a
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
            The ``**kwargs`` absorbs the keywords :meth:`Protocol.__post_init__
            <pcapkit.protocols.protocol.Protocol.__post_init__>` hands to the
            parse as well as the construction, so an implementation need not
            declare every keyword it is called with. A caller's keyword that no
            signature declares still raises
            :exc:`~pcapkit.utilities.exceptions.UnexpectedKeyword` from a
            construction (:issue:`617`).

        Warning:
            **Calling this method directly is not checked**, and discards an
            undeclared keyword silently. The check lives in :meth:`from_fields`,
            :meth:`from_data` and a call of the class given no file, which hand
            the keywords on, so it covers ``SomeProtocol(...)`` and its
            :meth:`pack`, but not ``object.__new__(cls).make(**kwargs)``, as
            :meth:`HTTP.make <pcapkit.protocols.application.http.protocol.HTTP.make>`
            calls its versioned implementation. Construct through one of those to
            get the check.

        .. versionchanged:: 1.8.0

           Every implementation takes its fields as keywords only
           (:issue:`2840`).

        """

    def pack(self, **kwargs: 'Any') -> 'bytes':
        """Pack (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Notes:
            The special keyword argument ``__packet__`` passes the global
            packet data to underlying methods, for when the current instance
            does not have it.

            The octets are built from ``kwargs`` alone, through :meth:`make`;
            the instance's state is not read, so a bare
            ``SomeProtocol(...).pack()`` returns a default header, not the
            instance's octets, which :attr:`data` holds.

            Nor is that state written. Once the instance is parsed or
            constructed, the header is made on a shallow copy (see
            :meth:`_packing_target`), so :attr:`schema`, :attr:`info` and
            anything :meth:`make` sets, such as
            :attr:`TCP.connection <pcapkit.protocols.transport.tcp.protocol.TCP.connection>`,
            still describe that packet. Only the call :meth:`__post_init__`
            makes to construct the instance keeps the header, for
            :meth:`unpack` to read back.

            When :meth:`from_data` rebuilds a header the capture cut short,
            that call cuts it back to the octets captured, through
            ``__short_read__`` and :meth:`Schema._cut_short_read
            <pcapkit.protocols.schema.Schema._cut_short_read>`
            (:issue:`2703`). :meth:`__post_init__` then drops that header, so
            :meth:`unpack` parses the octets back and the rebuild holds the
            values its parse read, not those :meth:`make` filled in past the
            cut (:issue:`2761`).

        .. versionchanged:: 1.5.0

           Calling it no longer replaces the instance's
           :attr:`__header__ <Protocol.__header__>`, which left :attr:`schema`
           disagreeing with :attr:`info` (:issue:`1769`).

        """
        kwargs = self._pack_keywords(kwargs)
        target = self._packing_target()
        header = target.__header__ = target.make(**kwargs)
        #: bool: If the made header may hold raw items (see :meth:`unpack`).
        target._make_raw = _passes_raw(kwargs) or any(  # pylint: disable=protected-access
            isinstance(header.get(name), bytes) for name in _schema_slots(type(header)))
        packet = kwargs.get('__packet__', {})  # packet data
        data = header.pack(packet)
        if target.__short_read__ is None:
            return data

        # NOTE: Cut back before ``unpack`` reads and verifies it, at the width
        # ``from_data`` passes on (#2703, #2761).
        header.__dict__['__short_read__'] = target.__short_read__
        header._cut_short_read()  # pylint: disable=protected-access
        return bytes(header)

    def unpack(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> '_PT':
        """Unpack (parse) packet data.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Notes:
            The special keyword argument ``__packet__`` passes the global
            packet data to underlying methods, for when the current instance
            does not have it.

            A :attr:`self.__header__ <Protocol.__header__>` already set, by
            :meth:`from_schema` or by the :meth:`pack` call of
            :meth:`__post_init__`, is kept, unless it holds raw :obj:`bytes`
            where parsing its packed octets yields a schema -- e.g. a raw
            option given to ``make()``, directly or inside a data model -- which
            :meth:`read` cannot consume; it is then replaced by the parsed one
            (:issue:`1312`).

            A header :meth:`from_data` rebuilds from a short read is parsed
            from the octets captured, its warnings discarded, and given its
            data model's ``__short_read__`` before :meth:`read` runs, as the
            record of a cut those octets may not show (:issue:`2761`).

            Parsed on its own rather than inside a frame, a layer is given the
            octets captured, so its header is unpacked with ``__data_end__``
            (see :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>`):
            a cut inside it is the short read it records, with no
            ``packet length < 0`` warning per field and no length resolved below
            zero (:issue:`2880`). A check :meth:`read` makes of a value the cut
            left asks :func:`~pcapkit.corekit.schema.short_read.cut_on_its_own`
            whether to leave it to the short read.

        Raises:
            ProtocolError: If the made header holds raw items and its packed
                octets do not parse, either as a schema or by :meth:`read`.
                The message carries the original error's, which is also
                chained as ``__cause__``.

        .. versionchanged:: 1.6.0

           A raw item that ``make()`` takes from inside a data model, such as
           the one :meth:`from_data` passes on, is replaced too, rather than
           reaching :meth:`read` (:issue:`2725`).

        .. versionchanged:: 1.7.0

           A layer parsed on its own unpacks its header as ending with the data,
           so a cut inside it warns nothing and resolves no length below zero
           (:issue:`2880`).

        """
        packet = kwargs.get('__packet__', {})  # packet data
        # NOTE: On its own a layer is given the octets captured, so the header it parses ends
        # with the data; inside a frame the frame's lengths say where it ends (#2880).
        if cast('Optional[_ST]', self.__header__) is None and not frame_depth.get():
            packet['__data_end__'] = True
        if cast('Optional[_ST]', self.__header__) is None and self.__short_read__ is not None:
            # NOTE: A rebuilt short read is parsed as quietly as its made header was read,
            # and keeps the record of a cut its octets may not show (#2711, #2761).
            with hold_warnings() as held:
                held.discard = True
                header = cast('_ST', self.__schema__.unpack(self._file, length, packet))  # type: ignore[call-arg,misc]
            header.__dict__['__short_read__'] = self.__short_read__
            self.__header__ = header
        elif cast('Optional[_ST]', self.__header__) is None:
            self.__header__ = cast('_ST', self.__schema__.unpack(self._file, length, packet))  # type: ignore[call-arg,misc]
        elif self._make_raw and _holds_raw(self.__header__):
            # NOTE: A schema may accept octets :meth:`read` rejects, e.g. an option
            # overrunning the option area, so the read is covered too (#1394).
            try:
                parsed = cast('_ST', type(self.__header__).unpack(io.BytesIO(self._data), length, packet))  # type: ignore[call-arg,misc]
                if _raw_where_parsed(self.__header__, parsed):
                    self.__header__ = parsed
                return self.read(length, **kwargs)
            except (BaseError, struct.error) as error:  # pylint: disable=no-member
                raise ProtocolError(f'{type(self).__name__}: malformed raw item given to make(): {error}') from error
        return self.read(length, **kwargs)

    @staticmethod
    def decode(byte: bytes, *, encoding: 'Optional[str]' = None,
               errors: 'Literal["strict", "ignore", "replace"]' = 'strict') -> 'str':
        """Decode :obj:`bytes` into :obj:`str`.

        Should decoding fail using ``encoding``, the method will try again decoding
        the :obj:`bytes` as ``'unicode_escape'`` with ``'replace'`` for error handling.

        See Also:
            The method is a wrapping function for :meth:`bytes.decode`.

        Args:
            byte: Source bytestring.
            encoding: The encoding with which to decode the :obj:`bytes`.
                If not provided, :mod:`pcapkit` will first try detecting its encoding
                using |chardet|_. The fallback encoding is **UTF-8**.
            errors: The error handling scheme to use for the handling of decoding errors.
                The default is ``'strict'`` meaning that decoding errors raise a
                :exc:`UnicodeDecodeError`. Other possible values are ``'ignore'`` and ``'replace'``
                as well as any other name registered with :func:`codecs.register_error` that
                can handle :exc:`UnicodeDecodeError`.

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

        Should decoding fail, the method will try again replacing ``'%'`` with ``'\\x'`` then
        decoding the ``url`` as ``'unicode_escape'`` with ``'replace'`` for error handling.

        See Also:
            This method is a wrapper function for :func:`urllib.parse.unquote`.

        Args:
            url: URL string.
            encoding: The encoding with which to decode the :obj:`bytes`.
            errors: The error handling scheme to use for the handling of decoding errors.
                The default is ``'replace'``, which substitutes a replacement marker for
                each undecodable sequence. Other possible values are ``'strict'``, under
                which decoding errors raise a :exc:`UnicodeDecodeError`, and ``'ignore'``,
                as well as any other name registered with :func:`codecs.register_error` that
                can handle :exc:`UnicodeDecodeError`.

        """
        try:
            return urllib.parse.unquote(url, encoding=encoding, errors=errors)
        except UnicodeError:
            return url.replace('%', r'\x').encode().decode('unicode_escape', errors='replace')

    @staticmethod
    def resolve_index(name: 'str | int | StdlibEnum | AenumEnum', default: 'Optional[int]' = None, *,
                      namespace: 'dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]',
                      reversed: 'bool' = False) -> 'int | StdlibEnum | AenumEnum':  # pylint: disable=redefined-builtin
        """Resolve a name for an enumeration field of :meth:`make`.

        A field of :meth:`make` that holds an enumeration takes a member or an
        :class:`int` code, and refuses a name (:issue:`2594`). This resolves a
        name against a ``namespace`` given explicitly, so that its result can
        be passed on::

           >>> from pcapkit.const.reg.ethertype import EtherType
           >>> from pcapkit.protocols.link.ethernet.protocol import Ethernet
           >>> code = Ethernet.resolve_index('Address_Resolution_Protocol',
           ...                               namespace=EtherType)
           >>> Ethernet(type=code).info.type
           <EtherType.Address_Resolution_Protocol: 2054>

        Args:
            name: a member name; a member or an :class:`int` is returned as
                it is, for :meth:`make` to resolve
            default: the code to return when ``name`` is not in ``namespace``
            namespace: the enumeration ``name`` names a member of, or a
                :obj:`dict` of codes and names
            reversed: if ``namespace`` is a :obj:`dict` of names to codes,
                rather than of codes to names

        Returns:
            The member ``name`` names, for an enumeration ``namespace``; the
            code it names, for a :obj:`dict`; else ``default``.

        Raises:
            ProtocolNotImplemented: If ``name`` is a :obj:`str` that is not in
                ``namespace`` and ``default`` is :data:`None`.

        .. versionadded:: 1.6.0

           Takes over the ``<field>_default``, ``<field>_namespace`` and
           ``<field>_reversed`` arguments of :meth:`make` (:issue:`2594`).

        """
        if not isinstance(name, str):
            return name
        try:
            if isinstance(namespace, type) and issubclass(namespace, (enum.Enum, aenum.Enum)):
                return namespace[name]
            if isinstance(namespace, dict):
                if reversed:
                    return cast('dict[str, int]', namespace)[name]
                return {value: key for key, value in cast('dict[int, str]', namespace).items()}[name]
            raise KeyError(name)  # caught below, so a non-mapping misses as an unknown name does
        except KeyError as error:
            if default is None:
                raise ProtocolNotImplemented(f'{name!r} is not a name in {namespace!r}') from error
            return default

    @staticmethod
    def expand_comp(value: 'str | ProtocolBase | Type[ProtocolBase]') -> 'tuple':
        """Expand protocol class to protocol name.

        The method is used to expand protocol class to protocol name, in the
        following manner:

        1. If ``value`` is a protocol instance, the method will return the
           protocol class, and the protocol names in upper case obtained from
           :meth:`Protocol.id <pcapkit.protocols.protocol.Protocol.id>`.
        2. If ``value`` is a protocol class, the method will return the
           protocol class itself, and the protocol names in upper case
           obtained from :meth:`Protocol.id <pcapkit.protocols.protocol.Protocol.id>`.
        3. If ``value`` is :obj:`str`, the method will attempt to search for
           the existing registered protocol class with
           :meth:`ProtocolBase.get_protocol` and follow **step 2**; otherwise,
           return the value in upper case alone.

        Args:
            value: Protocol class or name.

        """
        if isinstance(value, type) and issubclass(value, ProtocolBase):
            comp = (value, *(name.upper() for name in value.id()))
        elif isinstance(value, ProtocolBase):
            comp = (type(value), *(name.upper() for name in value.id()))
        elif (proto := ProtocolBase.get_protocol(value)) is not None:
            comp = (proto, *(name.upper() for name in proto.id()))
        else:
            comp = (value.upper(),)
        return comp

    @classmethod
    def analyze(cls, proto: 'int', payload: 'bytes', /, *,
                layer: 'Optional[str]' = None,
                protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
                ) -> 'ProtocolBase':
        """Analyse packet payload.

        Args:
            proto: Protocol registry number.
            payload: Packet payload.
            layer: Parse the payload until such layer, as for :meth:`__init__`.
            protocol: Parse the payload until such protocol, as for
                :meth:`__init__`.
            context: Caller supplied parsing context, as for :meth:`__init__`.

        Returns:
            Parsed payload as a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            instance. A payload that fails to parse is kept as
            :class:`~pcapkit.protocols.misc.raw.protocol.Raw` holding all of it,
            its ``error`` the failure's message and its ``protocol`` ``proto``,
            or as :class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload`
            after an end-of-file :exc:`~pcapkit.utilities.exceptions.StructError`.
            A refusal it absorbs is quiet, any other error is logged at
            :data:`logging.WARNING`, and the failed parse's warnings are dropped,
            as :meth:`_analyze_next_layer` describes. An empty payload is
            :class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload`, as in a
            frame. A payload past a stop this class meets is ``Raw``, as a frame
            keeps the next layer of the layer it stops at.

        Raises:
            FormatError: If ``layer`` names no layer.
            RegistryError: If ``protocol`` is no protocol name, class or instance.

        Note:
            Called by :meth:`_analyze_from_parent`, it hands the payload the
            next-layer state that method was given, as a frame's layer hands its
            own (:issue:`2945`).

        .. versionchanged:: 1.7.0

           The fallback holds the whole payload and the failure's message,
           rather than the octets the failed parse left unread (:issue:`2842`).
           Its ``protocol`` is ``proto``, a refusal it absorbs is quiet, any
           other error is logged at :data:`logging.WARNING`, and the failed
           parse's warnings are dropped (:issue:`2862`). An empty payload is
           ``NoPayload`` (:issue:`2880`). A payload past a stop is ``Raw``, and
           the parse gets ``proto`` as ``alias``, as a frame's next layer does
           (:issue:`2933`).

        .. versionchanged:: 1.8.0

           ``proto`` and ``payload`` are positional-only, and the keywords are
           those of :meth:`__init__`, ``layer``, ``protocol`` and ``context``,
           so any other is refused (:issue:`2840`).

        """
        klass = cls._analyze_stop(layer, protocol) or cls._lookup_next_layer(cls.__proto__, proto)
        return cls._analyze_next_layer(klass, payload, proto, layer=layer, protocol=protocol, context=context)

    @classmethod
    def register(cls, code: 'int', protocol: 'ModuleDescriptor | Type[ProtocolBase]') -> 'None':
        r"""Register a new protocol class.

        Notes:
            The fully qualified class name of the new protocol class
            should be ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: protocol code
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If ``code`` holds a
                different entry, naming the displaced one and its replacement.
                An unresolved :class:`~pcapkit.corekit.module.ModuleDescriptor`
                incumbent counts as different from the class it names.

        Note:
            As for :func:`register_protocol
            <pcapkit.foundation.registry.protocols.protocol.register_protocol>`,
            handing back the entry stored under ``code`` -- the same class
            object, or an equal
            :class:`~pcapkit.corekit.module.ModuleDescriptor` -- is a silent
            no-op that keeps the stored entry (:issue:`1364`). The comparison
            resolves nothing, so a stored descriptor stays deferred.

            A descriptor equal to the one ``code`` shipped with restores that
            shipped object, unresolved, so undoing an override leaves the entry
            as shipped (:issue:`1504`); see ``_next_layer_entry()``, which
            every layer's ``register`` shares.

        """
        incumbent = cls.__proto__.get(code)
        entry = cls._next_layer_entry(code, protocol)
        if entry is None:
            return
        if incumbent is not None and incumbent is not entry:
            warn(f'protocol {code} already registered, overwriting '
                 f'{incumbent!r} with {entry!r}', RegistryWarning)
        cls.__proto__[code] = entry

    @classmethod
    def register_protocol(cls, protocol: 'Type[ProtocolBase]') -> 'None':
        """Register a protocol class in :attr:`__registry__`, replacing what its name holds.

        The key is ``protocol.__name__.upper()``. Defining a concrete
        :class:`Protocol` subclass registers it already, but keeps an entry its
        name holds, so this is how to replace one, or to register a class that
        derives :class:`ProtocolBase` alone.

        Arguments:
            protocol: :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If the name holds a
                different class, naming it and its replacement, and their ids
                where the two read the same. A
                :class:`~pcapkit.corekit.module.ModuleDescriptor` entry is
                resolved to compare, so registering the class it names is silent
                and leaves the descriptor in place.

        Note:
            A built-in protocol is stored as the descriptor it shipped as, per
            :attr:`_shipped_registry`, rather than as its class, so undoing an
            override leaves the entry as shipped, to be imported on lookup.

        .. versionadded:: 1.6.0

        """
        if not isinstance(protocol, type):
            raise RegistryError(f'protocol must be a class, not {protocol!r}')
        if not issubclass(protocol, ProtocolBase):
            raise RegistryError(f'protocol must be a Protocol subclass, not {protocol!r}')

        name = protocol.__name__.upper()
        incumbent = ProtocolBase.get_protocol(name)
        if incumbent is protocol:
            return
        if incumbent is not None:
            incumbent_repr, protocol_repr = repr(incumbent), repr(protocol)
            if incumbent_repr == protocol_repr:
                # NOTE: #710: distinct classes can share a repr(), e.g. a factory's
                # fresh class of one name per call; id() tells them apart.
                incumbent_repr = f'{incumbent_repr} (id={id(incumbent):#x})'
                protocol_repr = f'{protocol_repr} (id={id(protocol):#x})'
            warn(f'protocol {name} already registered, overwriting {incumbent_repr} '
                 f'with {protocol_repr}', RegistryWarning)
        shipped = ProtocolBase._shipped_registry.get(name)
        if isinstance(shipped, ModuleDescriptor) and \
                (shipped.module, shipped.name) == (protocol.__module__, protocol.__name__):
            ProtocolBase.__registry__[name] = shipped
        else:
            ProtocolBase.__registry__[name] = protocol

    @overload  # pragma: no cover
    @classmethod
    def get_protocol(cls, name: 'str') -> 'Optional[Type[ProtocolBase]]': ...
    @overload  # pragma: no cover
    @classmethod
    def get_protocol(cls, name: 'str', default: '_VT') -> 'Type[ProtocolBase] | _VT': ...

    @classmethod
    def get_protocol(cls, name: 'str', default: 'Any' = None) -> 'Any':
        """Look a protocol class up in :attr:`__registry__` by name.

        Arguments:
            name: protocol name, in any case: ``'ipv4'`` finds
                :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`
            default: what to return where no entry has the name

        Returns:
            The class registered under ``name.upper()``, imported where its entry
            is a :class:`~pcapkit.corekit.module.ModuleDescriptor`, or
            ``default``. The entry is left as it is, so a descriptor is resolved
            again on each lookup and follows a reloaded module.

        Raises:
            pcapkit.utilities.exceptions.ProtocolError: If a descriptor names a
                class its module does not define.

        .. versionadded:: 1.6.0

        """
        entry = ProtocolBase.__registry__.get(name.upper())
        if entry is None:
            return default
        if isinstance(entry, ModuleDescriptor):
            return entry.klass
        return entry

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
    def from_file(cls, file: 'IO[bytes] | bytes', length: 'Optional[int]' = None, /, *,
                  layer: 'Optional[str]' = None,
                  protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                  context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
                  **keywords: 'Any') -> 'Self':
        """Parse a protocol instance from ``file``, its octets as bytes or a binary stream.

        The explicit form of calling the class with ``file``, giving the same
        result: through a versioned family's base, the member the parse picks
        (:ref:`protocol-family-dispatch`). A field is refused (:issue:`3081`).
        ``file`` is no path to a capture file, which :func:`~pcapkit.interface.core.extract`
        reads.

        Args:
            file: Source packet stream: :obj:`bytes`, or a binary stream read from
                its current position.
            length: Length of packet data.
            layer: As :meth:`__init__`.
            protocol: As :meth:`__init__`; a stop, never a field.
            context: As :meth:`__init__`.
            **keywords: The parse keywords of the class's own :meth:`__init__`,
                such as the ``version`` of a versioned family's base.

        Returns:
            Protocol instance.

        Raises:
            TypeError: If ``file`` is :obj:`None`, or a keyword is none the parse
                of this class takes, a field included.
            FormatError: If ``layer`` names no layer.
            RegistryError: If ``protocol`` is no protocol name, class or instance.

        .. versionadded:: 1.8.0

        """
        # NOTE: Typed as a callable, since mypy finds an abstract class with an overloaded
        # ``__init__`` uninstantiable through ``cls`` (#3081).
        call = cls  # type: Callable[..., Self]
        return call(file, length, layer=layer, protocol=protocol, context=context, **keywords)

    @classmethod
    def from_fields(cls, *,
                    context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
                    **fields: 'Any') -> 'Self':
        """Construct a protocol instance from its fields.

        The fields are the keywords of :meth:`make`, and any other a hook of
        this protocol declares, as
        :func:`~pcapkit.protocols.protocol._declared_keywords` collects them.
        Through a versioned family's base, ``version`` names the member built
        (:ref:`protocol-family-dispatch`).

        Args:
            context: Caller supplied context (see
                :mod:`pcapkit.corekit.context`), as for a parse, such as the
                Security Associations :class:`~pcapkit.protocols.internet.esp.protocol.ESP`
                encrypts with.
            **fields: Fields of the protocol.

        Returns:
            Protocol instance; through a versioned family's base, one of the
            member ``version`` names.

        Raises:
            UnexpectedKeyword: If a keyword is none this protocol declares;
                ``file``, ``length``, ``layer`` and ``protocol`` count only where a
                ``make`` field has that name, and ``__context__`` never does.
            ProtocolError: Through a versioned family's base, if ``version`` is
                missing or names no member; on a member, if it names another.

        .. versionadded:: 1.8.0

        """
        klass = cls._construction_member(fields)
        # NOTE: ``_construct``, inline, as a parse ends in ``NoPayload.from_fields()``
        # and so would gain a frame (#1610).
        _check_construction_keywords(klass, fields)
        self = klass.__new__(klass)
        self._initialise(context=context)
        if 'file' in fields or 'length' in fields:
            self.__named_fields__ = _named_fields(fields)
        self.__post_init__(**fields)
        self._info.__update__(packet=self.packet.payload)
        return self

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', /, *,
                  context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
                  **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        ``data`` may be the :obj:`dict` that :meth:`Info.to_dict
        <pcapkit.corekit.infoclass.Info.to_dict>` returns, which carries the
        metadata the rebuild reads: ``__next_name__`` and ``__next_type__``,
        which the payload is dispatched on, ``__short_read__`` and
        ``__short_width__``, and, for
        :class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6`, the extension
        header chain under ``__exthdr__``. A hand-written :obj:`dict` without
        them rebuilds no payload (nor IPv6 extension header) and cuts no short
        read back; nothing is guessed from its other keys (see
        :meth:`_make_payload`, :issue:`2003`).

        A header the capture cut short, as ``__short_read__`` records, is cut
        back and read at the width ``__short_width__`` records, so the rebuild
        parses the octets captured as the capture did (:issue:`2703`): it holds
        the values its parse read, not those :meth:`make` fills in past the cut
        (:issue:`2761`), and the ``Raw`` next layer that parse left
        (:issue:`2717`). Inside a payload :meth:`_make_payload` rebuilds, which
        gives only its octets, the header made is read instead.

        Args:
            data: Protocol data.
            context: Caller supplied context, as for :meth:`from_fields`.
            **kwargs: Construction keywords that ``data`` does not carry, such as
                the ``num`` and ``header`` of
                :class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame`, or the
                ``num``, ``sct`` and ``ctx`` of
                :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG`. They take
                precedence over the keywords :meth:`_make_data` returns.

        Returns:
            Protocol instance.

        Raises:
            UnexpectedKeyword: If any of ``kwargs`` matches no parameter of the
                protocol, as for :meth:`from_fields`.

        Warns:
            UnknownFieldWarning: If a keyword :meth:`_make_data` returns matches
                none, which the caller cannot correct.

        .. versionchanged:: 1.8.0

           ``data`` is positional-only, the context is ``context`` rather than
           ``__context__``, and the stops ``_layer`` and ``_protocol`` are
           refused (:issue:`2840`).

        """
        if not isinstance(data, Data):
            data = cast('_PT', cls.__data__.from_dict(data))

        # NOTE: The caller's own keywords are checked strictly, as for ``from_fields``;
        # the rest came from ``_make_data``, so they warn, not raise.
        _check_construction_keywords(cls, kwargs)
        keywords = {**cls._make_data(data), **kwargs}
        klass = cls._construction_member(keywords)
        _check_construction_keywords(klass, keywords, strict=False)

        self = klass.__new__(klass)
        # NOTE: For the call alone; ``pack`` cuts back by it (#2703). A cut header is read at
        # the width its parse read it at, so the rebuild holds what its parse did (#2717, #2761).
        self.__short_read__ = cast('Optional[tuple[str, int]]', data.get('__short_read__'))
        width = None if self.__short_read__ is None else data.get('__short_width__')
        try:
            self._initialise(context=context)
            if 'file' in keywords or 'length' in keywords:
                self.__named_fields__ = _named_fields(keywords)
            self.__post_init__(None, width, **keywords)  # type: ignore[call-overload]
            self._info.__update__(packet=self.packet.payload)
        finally:
            del self.__short_read__

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
        #: bool: If a header set before :meth:`unpack` may hold raw items;
        #: :meth:`pack` narrows it down for a made one.
        self._make_raw = True

        return self

    @overload  # pragma: no cover
    def __init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., /, *,
                 layer: 'Optional[str]' = ...,
                 protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = ...,
                 context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = ...,  # pylint: disable=line-too-long
                 ) -> 'None': ...
    @overload  # pragma: no cover
    def __init__(self, *,
                 context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = ...,  # pylint: disable=line-too-long
                 **fields: 'Any') -> 'None': ...

    # NOTE: mypy reads ``**fields`` as able to hold ``file``, which ``/`` keeps out of the
    # positional parameters, so it finds the construct overload unmet (#3081).
    def __init__(self, file: 'IO[bytes] | bytes | NoValueType' = NO_VALUE,  # type: ignore[misc]
                 length: 'Optional[int]' = None, /, *,
                 layer: 'Optional[str]' = None,
                 protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                 context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
                 **fields: 'Any') -> 'None':
        """Parse a protocol instance from its octets, or construct one from its fields.

        Given ``file``, it parses, as :meth:`from_file` does; given none, it
        constructs, as :meth:`from_fields` does (:issue:`3081`).

        Args:
            file: Source packet stream; omitted to construct.
            length: Length of packet data.
            layer: Parse packet until such layer
                (:attr:`self._exlayer <pcapkit.protocols.protocol.Protocol._exlayer>`):
                ``'link'``, ``'internet'``, ``'transport'`` or ``'application'``,
                in any case; :obj:`None` sets no stop.
            protocol: Parse packet until such protocol
                (:attr:`self._exproto <pcapkit.protocols.protocol.Protocol._exproto>`),
                given as a protocol name (:obj:`str`), a protocol class or a
                protocol instance; :obj:`None` sets no stop. Given no ``file``,
                a field where the class takes one of that name, as
                :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4` does.
            context: Caller supplied parsing context (:attr:`self._exctx
                <pcapkit.protocols.protocol.Protocol._exctx>`; see
                :mod:`pcapkit.corekit.context`): a
                :class:`~pcapkit.corekit.context.ContextRegistry`, a
                :class:`~pcapkit.corekit.context.ProtocolContext`, a mapping of
                names to :class:`~pcapkit.corekit.context.ProtocolContext`, or an
                iterable of :class:`~pcapkit.corekit.context.ProtocolContext`.
                It is propagated to nested layers by
                :meth:`self._import_next_layer
                <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
            **fields: Fields of the protocol, given no ``file``.

        Raises:
            TypeError: If ``file`` is :obj:`None`; if a field comes with a
                ``file``; or, given no ``file``, if ``length``, or a ``layer`` or
                ``protocol`` the class takes no field for, is given, since a
                construction takes no stop.
            FormatError: If ``layer`` names no layer.
            RegistryError: If ``protocol`` is no protocol name, class or instance.
            UnexpectedKeyword: Given no ``file``, if a field is none this
                protocol declares, as for :meth:`from_fields`. A ``file=`` or
                ``length=`` keyword is such a field, never the positional
                parameter of its name (:issue:`3081`).

        Note:
            A protocol whose parse takes a keyword of its own, such as the
            ``version`` of a versioned family's base, overrides this method with
            that keyword first, then ``layer``, ``protocol``, ``context`` and
            ``**fields``. Given a file, it calls :meth:`_parse`; given none, it
            adds its keyword to the fields where it is one, and calls
            :meth:`_construct` with :meth:`_call_fields`.

            The state the enclosing layer hands on through :meth:`_from_parent`,
            on :attr:`__next_layer__`, reaches :meth:`__post_init__` and the
            hooks after it as keywords (:issue:`2840`).

        .. versionchanged:: 1.8.0

           ``file`` and ``length`` are positional-only, and ``layer``,
           ``protocol`` and ``context`` keyword-only. A parse refuses any other
           keyword, ``_layer``, ``_protocol``, ``__context__``, ``packet`` and
           ``__packet__`` included, and a construction checks its fields as
           :meth:`from_fields` does. ``'none'`` and ``'null'`` no longer mean no
           stop (:issue:`2840`, :issue:`3081`).

        """
        if isinstance(file, NoValueType):
            self._construct(context, self._call_fields(length, layer, protocol, fields))
            return
        # NOTE: ``_parse``, inline, so a parse adds no frame per layer (#1610).
        keywords = self._start_parse(file, layer, protocol, context, {}, fields)
        self.__post_init__(file, length, **keywords)
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

        Note:
            Inside a payload :meth:`_make_payload` rebuilds, the parse's
            warnings are dropped, since the enclosing layer parses the same
            octets again and reports them (:issue:`2711`). A parse that raises
            reports its warnings, unless
            :func:`~pcapkit.corekit.decorators.beholder` replaces the layer.

        """
        if file is None:
            _data = self.pack(**kwargs)
            # NOTE: A short read's header is rebuilt from what was captured, at ``from_data``'s width,
            # not from ``make``'s fill past the cut (#2703, #2761); a rebuilt payload keeps its octets.
            if self.__short_read__ is not None and not rebuilding.get():
                self.__header__ = None  # type: ignore[assignment]
        else:
            _data = file if isinstance(file, bytes) else file.read(length)  # type: ignore[arg-type]

        #: bytes: Raw packet data.
        self._data = _data
        #: io.BytesIO: Source packet stream.
        self._file = io.BytesIO(self._data)
        if not rebuilding.get():
            #: pcapkit.protocols.data.Data: Parsed packet data.
            self._info = self.unpack(length, **kwargs)
            return

        # NOTE: The enclosing layer parses these octets again and reports what
        # they carry; as in ``_parse_next_layer``, a raise keeps them (#2711).
        with hold_warnings() as held:
            try:
                self._info = self.unpack(length, **kwargs)
            except Exception:
                held.discard = beholding.get()
                raise
            held.discard = True

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

        Sets :attr:`self.__schema__ <pcapkit.protocols.protocol.Protocol.__schema__>`
        and :attr:`self.__data__ <pcapkit.protocols.protocol.Protocol.__data__>`
        on the subclass and, if ``code`` is given, registers it into the
        next-layer dispatch :term:`registry` (or registries) ``code`` names,
        e.g. :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`.

        Notes:
            An omitted ``schema`` or ``data`` is the class of the subclass's
            own name in the ``schema`` or ``data`` module beside the
            ``protocol`` module defining it, as
            :class:`~pcapkit.protocols.link.l2tp.protocol.L2TP` finds
            :class:`~pcapkit.protocols.link.l2tp.schema.L2TP`
            (:issue:`2534`), else
            :class:`~pcapkit.protocols.misc.raw.schema.Raw` or
            :class:`~pcapkit.protocols.misc.raw.data.Raw`.

        Dispatch registration is **opt-in**, like the ``engine=``/``protocol=``/
        ``fmt=`` keywords of :class:`~pcapkit.foundation.engines.engine.Engine`,
        :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly`,
        :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` and
        :class:`~pcapkit.dumpkit.common.Dumper`. Every built-in protocol omits
        ``code``: the built-in dispatch tables (e.g. :attr:`Link.__proto__
        <pcapkit.protocols.link.link.Link.__proto__>`) are literal assignments
        in each layer module. A class defined without ``code`` can be
        registered later through the owning class's :meth:`register` or the
        matching ``register_*`` helper in
        :mod:`pcapkit.foundation.registry.protocols`.

        ``code`` accepts:

        * a single enum member, whose *type* determines the destination
          registry (or registries) -- e.g. any
          :class:`~pcapkit.const.reg.ethertype.EtherType` member always means
          :class:`~pcapkit.protocols.link.link.Link`, and any
          :class:`~pcapkit.const.reg.linktype.LinkType` member means *both*
          :class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame` **and**
          :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG`;
        * a :class:`dict` mapping a destination class to a key, for a key
          that cannot name its own destination -- a raw :class:`int` port,
          for instance, is ambiguous between
          :class:`~pcapkit.protocols.transport.tcp.protocol.TCP` and
          :class:`~pcapkit.protocols.transport.udp.protocol.UDP`, and *must* use this
          form;
        * an iterable mixing either of the above, to register the same class
          into several registries from a single declaration -- e.g. a
          :class:`~pcapkit.protocols.link.l2tp.protocol.L2TP` subclass reachable both
          by its IP protocol number and by a UDP port.

        The mapping form is accepted even where the key's type could be
        inferred. An enum member whose type names no known destination raises
        :exc:`~pcapkit.utilities.exceptions.RegistryError` rather than guessing.

        See Also:
            :func:`pcapkit.foundation.registry.protocols.protocol.register_protocol_code`
            implements the resolution described above.

        """
        if args or kwargs:
            unexpected = ', '.join([*map(repr, args), *sorted(kwargs)])
            raise UnsupportedCall(f'{cls.__name__}: unexpected class keyword(s): {unexpected}')

        super().__init_subclass__()

        if schema is None:
            schema = cast('Type[_ST]', _sibling_model(cls, 'schema'))
        if data is None:
            data = cast('Type[_PT]', _sibling_model(cls, 'data'))

        cls.__schema__ = schema
        cls.__data__ = data

        # NOTE: Copy a class's own ``__proto__`` before anything registers into it, so
        # ``_next_layer_entry`` restores a shipped descriptor unresolved (#1504).
        if '__proto__' in cls.__dict__:
            table = cls.__dict__['__proto__']
            cls._shipped_proto = types.MappingProxyType(
                dict(table) if isinstance(table, collections.abc.Mapping) else {})

        if code is not None:
            from pcapkit.foundation.registry.protocols import \
                register_protocol_code  # pylint: disable=import-outside-toplevel

            register_protocol_code(cls, code)

    def __repr__(self) -> 'str':
        """Returns representation of parsed protocol data.

        Example:
            >>> protocol
            <Frame frame=<Frame ..., ethernet=Ethernet(...), protocols='Ethernet:IPv6:Raw', packet=b'...'>>

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
            <Frame frame=<Frame ..., ethernet=Ethernet(...), protocols='Ethernet:IPv6:Raw', packet=b'...'>>
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
        from pcapkit.protocols.misc.no_payload.protocol import \
            NoPayload  # pylint: disable=import-outside-toplevel

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
        from pcapkit.protocols.misc.no_payload.protocol import \
            NoPayload  # pylint: disable=import-outside-toplevel

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
            other: Comparison against the object.

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

    @classmethod
    def _make_data(cls, data: 'Data') -> 'dict[str, Any]':
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction: those of ``data``, but
            the ``packet`` :meth:`__init__` puts into every parsed ``_info``,
            unless this protocol declares a ``packet`` keyword.

        .. versionchanged:: 1.8.0

           ``packet`` is left out unless declared, since :meth:`from_fields`
           refuses it then (:issue:`2840`).

        """
        keywords = data.to_dict()
        declared = _declared_keywords(cls)
        if declared is not None and 'packet' not in declared:
            keywords.pop('packet', None)
        return keywords

    def _pack_keywords(self, kwargs: 'dict[str, Any]') -> 'dict[str, Any]':
        """The keywords :meth:`pack` hands :meth:`make`.

        Args:
            kwargs: The keywords :meth:`pack` is given.

        Returns:
            ``kwargs``, with :attr:`__named_fields__` taken over them where a
            construction set it (:issue:`3081`).

        Note:
            A :meth:`pack` override that calls :meth:`make` itself calls this
            first, as those of PCAP and PCAP-NG frames do.

        .. versionadded:: 1.8.0

        """
        named = self.__dict__.pop('__named_fields__', None)
        return kwargs if named is None else {**kwargs, **named}

    def _packing_target(self) -> 'Self':
        """Return the instance that :meth:`pack` makes its header on.

        Returns:
            The instance itself while it is being constructed, i.e. before
            :meth:`__post_init__` has set its :attr:`info`, since its
            :meth:`unpack` reads the made header back; a shallow copy of it
            otherwise, so that neither that header nor an attribute that
            :meth:`make` sets is left on the instance (:issue:`1769`).

        Note:
            A :meth:`pack` override that does not call this one has to build
            on this target too, as :meth:`Frame.pack
            <pcapkit.protocols.misc.pcap.frame.protocol.Frame.pack>` and
            :meth:`PCAPNG.pack <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.pack>` do.
            The copy is shallow, so a :meth:`make` that mutates a container
            in place still reaches the instance's.

        """
        # NOTE: ``_info`` is the last thing ``__post_init__`` sets, from
        # ``unpack``; until then the instance holds no packet to keep.
        if '_info' not in vars(self):
            return self
        return copy.copy(self)

    @classmethod
    def _construction_member(cls, fields: 'dict[str, Any]') -> 'Type[Self]':  # pylint: disable=unused-argument
        """The class :meth:`from_fields`, :meth:`from_data` and a call given no file construct.

        A versioned family's base overrides it to pick its member, taking out of
        ``fields`` a ``version`` that only names the member
        (:ref:`protocol-family-dispatch`).

        Args:
            fields: Construction keywords.

        Returns:
            This class.

        .. versionadded:: 1.8.0

        """
        return cls

    @classmethod
    def _call_fields(cls, length: 'Optional[int]', layer: 'Optional[str]',
                     protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]',
                     fields: 'dict[str, Any]') -> 'dict[str, Any]':
        """The fields a call of this class given no file constructs from.

        ``layer`` and ``protocol`` are fields where :meth:`from_fields` takes one of
        that name, as it does ``protocol`` on
        :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`, and stops
        otherwise, which a construction does not take (:issue:`2840`).

        Args:
            length: Length of packet data, as the call gives it.
            layer: As the call gives it.
            protocol: As the call gives it.
            fields: The other construction keywords, updated in place.

        Returns:
            ``fields``, checked by :meth:`_construction_member`.

        Raises:
            TypeError: If ``length``, or a ``layer`` or ``protocol`` that is no
                field, is not :obj:`None`.
            ProtocolError: As :meth:`_construction_member` raises it.

        .. versionadded:: 1.8.0

        """
        declared = _declared_keywords(cls)
        stops = [] if length is None else ['length']
        for name, value in (('layer', layer), ('protocol', protocol)):
            if value is None:
                continue
            if declared is None or name in declared:
                fields[name] = value
            else:
                stops.append(name)
        if stops:
            raise _stops_without_a_file(cls, stops)
        cls._construction_member(fields)
        return fields

    def _construct(self, context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]',  # pylint: disable=line-too-long
                   fields: 'dict[str, Any]') -> 'None':
        """Construct this instance from its fields.

        :meth:`__init__` given no file calls it, and :meth:`from_fields` runs its
        steps inline, so a construction checks its fields the same way either way
        (:issue:`3081`).

        Args:
            context: Caller supplied context.
            fields: Construction keywords.

        Raises:
            UnexpectedKeyword: If a keyword is none this protocol declares.

        .. versionadded:: 1.8.0

        """
        _check_construction_keywords(type(self), fields)
        self._initialise(context=context)
        if 'file' in fields or 'length' in fields:
            self.__named_fields__ = _named_fields(fields)
        self.__post_init__(**fields)
        self._info.__update__(packet=self.packet.payload)

    def _initialise(self, layer: 'Optional[str]' = None,
                    protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                    context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
                    ) -> 'None':
        """Set the stops, the context and the termination flag of this instance.

        :meth:`_start_parse`, :meth:`_construct`, :meth:`from_fields` and
        :meth:`from_data` each call it, and :meth:`__post_init__` is called after
        it rather than from it, so it adds no frame to a parse, which dissects its
        next layer from inside its own (:issue:`1610`).

        Args:
            layer: Parse packet until such layer.
            protocol: Parse packet until such protocol.
            context: Caller supplied parsing context.

        .. versionadded:: 1.8.0

        """
        self._seekset = io.SEEK_SET
        self._exlayer = layer
        self._exproto = protocol
        # NOTE: A registry is adopted as-is rather than copied by ``make()``: the
        # contexts are shared across layers regardless.
        self._exctx = (context if isinstance(context, ContextRegistry)
                       else ContextRegistry.make(context))
        self._sigterm = self._check_term_threshold()

    def _start_parse(self, file: 'Optional[IO[bytes] | bytes]', layer: 'Optional[str]',
                     protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]',
                     context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]',  # pylint: disable=line-too-long
                     keywords: 'dict[str, Any]', fields: 'Mapping[str, Any]') -> 'dict[str, Any]':
        """Check what a parse is given and set its stops and context.

        :meth:`__init__`, :meth:`_parse` and the overrides that run its steps
        inline call it and then :meth:`__post_init__` themselves, as
        :meth:`_initialise` explains.

        Args:
            file: Source packet stream.
            layer: Parse packet until such layer.
            protocol: Parse packet until such protocol.
            context: Caller supplied parsing context.
            keywords: The parse keywords of the class's own :meth:`__init__`.
            fields: The other keywords :meth:`__init__` is given, which a parse
                refuses (:issue:`3081`).

        Returns:
            The keywords for :meth:`__post_init__`: ``keywords``, with the
            :attr:`__next_layer__` state over them, and a copy of its ``packet``
            as ``__packet__``.

        Raises:
            TypeError: If ``file`` is :obj:`None`, or ``fields`` is not empty.
            FormatError: If ``layer`` names no layer.
            RegistryError: If ``protocol`` is no protocol name, class or instance.

        .. versionadded:: 1.8.0

        """
        if file is None:
            raise _nothing_to_parse(type(self))
        if fields:
            raise _fields_with_a_file(type(self), fields)
        self._check_stops(layer, protocol)

        # NOTE: The enclosing layer's state wins, so a default an override passes on cannot mask it.
        state = self.__dict__.pop('__next_layer__', None)
        if state:
            keywords.update(state)
        self._initialise(layer, protocol, context)

        # NOTE: ``packet`` from ``_import_next_layer`` reaches the schema as ``__packet__`` (GH-382),
        # copied since ``Schema.unpack`` writes into it and IPv6 extension headers share one dict.
        if '__packet__' not in keywords and isinstance(keywords.get('packet'), dict):
            keywords['__packet__'] = dict(keywords['packet'])
        return keywords

    def _parse(self, file: 'IO[bytes] | bytes', length: 'Optional[int]', fields: 'Mapping[str, Any]', /, *,
               layer: 'Optional[str]' = None,
               protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
               context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
               **keywords: 'Any') -> 'None':
        """Parse this instance as :meth:`__init__` does, with parse keywords of its class's own.

        An :meth:`__init__` override taking such a keyword calls this, as
        :meth:`IP.__init__ <pcapkit.protocols.internet.ip.protocol.IP.__init__>`
        does for ``version``, since the base's keywords are closed (:doc:`/ext`).
        Calling it adds a frame to a layer's parse, so :meth:`__init__` runs its
        steps inline, and so do the library's overrides, but for the versioned bases
        that call it, as :meth:`IPv6_Ext.__init__
        <pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext.__init__>` does
        (:issue:`1610`).

        Args:
            file: Source packet stream.
            length: Length of packet data.
            fields: The other keywords the override is given, which a parse
                refuses (:issue:`3081`).
            layer: Parse packet until such layer.
            protocol: Parse packet until such protocol.
            context: Caller supplied parsing context.
            **keywords: The override's own parse keywords, for
                :meth:`__post_init__` and the hooks after it.

        Raises:
            TypeError: If ``file`` is :obj:`None`, or ``fields`` is not empty.
            FormatError: If ``layer`` names no layer.
            RegistryError: If ``protocol`` is no protocol name, class or instance.

        .. versionadded:: 1.8.0

        """
        keywords = self._start_parse(file, layer, protocol, context, keywords, fields)
        self.__post_init__(file, length, **keywords)
        self._info.__update__(packet=self.packet.payload)

    @classmethod
    def _next_layer_entry(cls, code: 'Any', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]'
                          ) -> 'Optional[ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]':
        """Work out what a next-layer ``register`` stores under ``code``.

        :meth:`register` and every override of it, such as
        :meth:`Link.register <pcapkit.protocols.link.link.Link.register>`,
        share this; each still warns and stores for itself.

        Arguments:
            code: registry key
            protocol: module descriptor or a :class:`ProtocolBase` subclass

        Returns:
            :obj:`None` if ``protocol`` is the entry stored under ``code``
            already -- the same object, or a descriptor equal to a stored one
            (:issue:`1364`). Otherwise the entry to store: if ``protocol`` is a
            descriptor equal to the one ``code`` shipped with, per
            :attr:`_shipped_proto`, the shipped object itself, unresolved;
            else ``protocol`` resolved to its class.

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`ProtocolBase` subclass.

        Note:
            The shipped descriptor is matched before it is resolved, so an
            override undone by handing back the shipped entry leaves the
            registry as it shipped: the entry is still a descriptor, nothing is
            imported, and the class is looked up when a frame dispatches to it
            (:issue:`1504`).

        """
        incumbent = cls.__proto__.get(code)
        if incumbent is not None and (incumbent is protocol or (
                isinstance(incumbent, ModuleDescriptor) and isinstance(protocol, ModuleDescriptor)
                and incumbent == protocol)):
            return None
        shipped = cls._shipped_proto.get(code)
        if (isinstance(protocol, ModuleDescriptor) and isinstance(shipped, ModuleDescriptor)
                and protocol == shipped):
            return shipped
        if isinstance(protocol, ModuleDescriptor):
            protocol = protocol.klass
        if not isinstance(protocol, type):
            raise RegistryError(f'protocol must be a class, not {protocol!r}')
        if not issubclass(protocol, ProtocolBase):
            raise RegistryError(f'protocol must be a Protocol subclass, not {protocol!r}')
        return protocol

    def _get_context(self, cls: 'Optional[Type[_CTX]]' = None) -> 'Optional[_CTX]':
        """Get the caller supplied context for this protocol, if any.

        The lookup is keyed on :meth:`self.id
        <pcapkit.protocols.protocol.Protocol.id>`, so a
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
            This is a wrapper function for :meth:`pcapkit.protocols.schema.Schema.get_payload`.

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
            StructError: If the buffer is empty, whatever ``quiet`` says, or if
                fewer than ``size`` octets were read, without ``quiet``.

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
        else:               # no struct format, see int.from_bytes below
            kind = None

        mem = self._file.read(size)
        if not mem:
            raise StructError('unpack: empty buffer', quiet=True, eof=True)

        if kind is None:
            # A short read fails here as :func:`struct.unpack` makes it fail
            # for the sizes that have a format code (#2279).
            if len(mem) < size and not quiet:
                raise StructError(f'{self.__class__.__name__}: unpack failed')
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

        Raises:
            StructError: If the buffer is empty, with ``eof`` set as by
                :meth:`_read_unpack`, or if fewer than ``size`` octets were read.

        """
        # ``max`` makes a non-positive size read nothing rather than the
        # rest of the stream.
        mem = self._file.read(max(size, 0))
        if len(mem) < size:
            if not mem:
                raise StructError('unpack: empty buffer', quiet=True, eof=True)
            raise StructError(f'{self.__class__.__name__}: unpack failed')
        return ''.join(bin(byte)[2:].zfill(8) for byte in mem)

    def _read_octets(self, data: 'bytes', pos: 'int' = 0, *, size: 'int', what: 'str') -> 'bytes':
        """Read exactly ``size`` octets out of ``data`` at ``pos``.

        A plain slice comes back short past the end of ``data``, which would
        let a truncated field parse rather than fail.

        Args:
            data: buffer being read
            pos: offset of the octets in ``data``
            size: octets to read
            what: name of the field, for the error message

        Returns:
            The ``size`` octets at ``pos``.

        Raises:
            ProtocolError: If fewer than ``size`` octets remain from ``pos``.
                The message names :attr:`alias`.

        .. versionadded:: 1.6.0

        """
        octets = data[pos:pos + size]
        if len(octets) != size:
            raise ProtocolError(f'{self.alias}: invalid format: {what} runs past the end of the buffer')
        return octets

    def _read_uint(self, data: 'bytes', pos: 'int' = 0, *, size: 'int', what: 'str',
                   lilendian: 'bool' = False) -> 'int':
        """Read a ``size``-octet unsigned integer out of ``data`` at ``pos``.

        :meth:`_read_unpack` reads the file; this reads a buffer already in
        hand. The inverse is :meth:`_make_pack`, not :meth:`_make_uint`, which
        checks a value and packs nothing.

        Args:
            data: buffer being read
            pos: offset of the integer in ``data``
            size: octets in the integer
            what: name of the field, for the error message
            lilendian: little-endian flag

        Returns:
            The integer.

        Raises:
            ProtocolError: If fewer than ``size`` octets remain from ``pos``,
                as :meth:`_read_octets` raises it.

        .. versionadded:: 1.6.0

        """
        octets = self._read_octets(data, pos, size=size, what=what)
        return int.from_bytes(octets, 'little' if lilendian else 'big')

    @staticmethod
    def _read_sint(value: 'int', bits: 'int') -> 'int':
        """Read ``value``, an unsigned ``bits``-bit field, as a two's-complement one.

        It takes the unsigned integer a field has already read, such as a
        :class:`~pcapkit.corekit.fields.strings.BitField` sub-field, rather
        than a buffer.

        Args:
            value: the unsigned value read from the field
            bits: width of the field, in bits

        Returns:
            The signed value the same bits denote.

        .. versionadded:: 1.6.0

        """
        return value - (1 << bits) if value & (1 << (bits - 1)) else value

    def _read_vector(self, data: 'bytes', pos: 'int' = 0, *, size: 'int' = 1,
                     what: 'str') -> 'tuple[bytes, int]':
        """Read a length-prefixed vector out of ``data``.

        The vector is a ``size``-octet unsigned big-endian length, then that
        many octets, as the variable-length vectors of TLS's presentation
        language are (:rfc:`9846#section-3.4`).

        Args:
            data: buffer being read
            pos: offset of the length prefix in ``data``
            size: octets in the length prefix
            what: name of the vector, for the error message

        Returns:
            The vector's octets, and the offset just past them.

        Raises:
            ProtocolError: If the length prefix, or the octets it counts, run
                past the end of ``data``. The message names :attr:`alias`.

        .. versionadded:: 1.6.0

        """
        start = pos + size
        end = start + self._read_uint(data, pos, size=size, what=f'{what} length')
        return self._read_octets(data, start, size=end - start, what=what), end

    def _read_whole_vector(self, data: 'bytes', *, size: 'int' = 1, what: 'str') -> 'bytes':
        """Read the one length-prefixed vector that ``data`` holds.

        The vector is read as :meth:`_read_vector` reads it from offset zero,
        and has to end where ``data`` does.

        Args:
            data: buffer holding the vector and nothing else
            size: octets in the length prefix
            what: name of the vector, for the error message

        Returns:
            The vector's octets.

        Raises:
            ProtocolError: If the vector runs past the end of ``data``, or
                octets follow it. The message names :attr:`alias`.

        .. versionadded:: 1.6.0

        """
        octets, end = self._read_vector(data, 0, size=size, what=what)
        if end != len(data):
            raise ProtocolError(f'{self.alias}: invalid format: {what} carries excess octets')
        return octets

    def _read_uints(self, data: 'bytes', *, size: 'int' = 1, what: 'str') -> 'tuple[int, ...]':
        """Read ``data`` as a run of ``size``-octet unsigned big-endian integers.

        Args:
            data: buffer holding the integers and nothing else
            size: octets in each integer
            what: name of the list, for the error message

        Returns:
            The integers, in order.

        Raises:
            ProtocolError: If the length of ``data`` is not a multiple of
                ``size``, whose trailing octets would otherwise be padded out
                when the list is made again. The message names :attr:`alias`.

        .. versionadded:: 1.6.0

        """
        if len(data) % size:
            raise ProtocolError(f'{self.alias}: invalid format: {what} length {len(data)} '
                                f'is not a multiple of {size}')
        return tuple(int.from_bytes(data[index:index + size], 'big') for index in range(0, len(data), size))

    def _read_mac_addr(self, addr: 'bytes') -> 'str':
        """Read a MAC address, an EUI-64 one included.

        Args:
            addr: the address octets

        Returns:
            Colon (``:``) separated *hex* encoded address.

        .. versionadded:: 1.6.0

        """
        return addr.hex(':')

    def _read_text(self, data: 'bytes') -> 'tuple[str, Optional[str]]':
        """Decode text, recording how to encode it back.

        The text is decoded by :meth:`decode`. Where the result does not
        encode back to ``data`` as UTF-8 -- which ``make()`` uses by default --
        the detected charset is returned with it, or ``'latin-1'`` (decoding
        again) if that does not reproduce ``data`` either, so that the original
        octets survive a rebuild.

        Args:
            data: raw text

        Returns:
            The decoded text and the charset to encode it with, the latter
            :obj:`None` for UTF-8.

        .. versionadded:: 1.6.0

        """
        value = self.decode(data)
        for charset in (None, detect(data)):
            try:
                if value.encode(charset or 'utf-8') == data:
                    return value, charset
            except (LookupError, UnicodeError):
                pass
        return data.decode('latin-1'), 'latin-1'

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

        * If ``header`` is omitted, returns the whole packet data in :obj:`bytes`.
        * If ``discard`` is set as :data:`True`, returns the packet body (in
          :obj:`bytes`) only.
        * Otherwise, returns the header and payload data as
          :class:`~pcapkit.protocols.data.Packet` object.

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
        if size == 8:                       # pack from 8-byte integer (long long)
            kind = 'q' if signed else 'Q'
        elif size == 4:                     # pack from 4-byte integer (int / long)
            kind = 'i' if signed else 'I'
        elif size == 2:                     # pack from 2-byte integer (short)
            kind = 'h' if signed else 'H'
        elif size == 1:                     # pack from 1-byte integer (char)
            kind = 'b' if signed else 'B'
        else:                               # no struct format, see int.to_bytes below
            kind = None

        if kind is None:
            end = 'little' if lilendian else 'big'  # type: Literal['little', 'big']
            # ``int.to_bytes`` raises these where ``struct.pack`` raises
            # ``struct.error`` for the other sizes (#2291).
            try:
                buf = integer.to_bytes(size, end, signed=signed)
            except (AttributeError, OverflowError, TypeError, ValueError) as error:
                raise StructError(f'{cls.__name__}: pack failed') from error
        else:
            try:
                fmt = f'{endian}{kind}'
                buf = struct.pack(fmt, integer)  # pylint: disable=no-member
            except struct.error as error:  # pylint: disable=no-member
                raise StructError(f'{cls.__name__}: pack failed') from error
        return buf

    def _make_octets(self, value: 'Any', *, size: 'int', name: 'str',
                     alias: 'Optional[str]' = None) -> 'bytes':
        """Check that ``value`` is exactly ``size`` octets.

        The octets :meth:`_read_octets` reads are written as they are, so
        their size is all there is to check.

        Args:
            value: the value given for the field
            size: octets in the field
            name: name of the field, for the error message
            alias: prefix of the error message, for a caller whose
                :attr:`alias` raises before ``read()`` sets it; :attr:`alias`
                by default

        Returns:
            ``value`` as :class:`bytes`.

        Raises:
            ProtocolError: If ``value`` is not :class:`bytes` or
                :class:`bytearray`, or is not ``size`` octets long. The
                message names ``alias``.

        .. versionadded:: 1.6.0

        """
        if not isinstance(value, (bytes, bytearray)) or len(value) != size:
            unit = 'octet' if size == 1 else 'octets'
            raise ProtocolError(f'{self.alias if alias is None else alias}: invalid {name}: '
                                f'must be {size} {unit}, not {value!r}')
        return bytes(value)

    @classmethod
    def _fill_short_read(cls, value: 'Any', *, size: 'int', model: 'Any', field: 'str',
                         offset: 'int' = 0) -> 'Any':
        """Zero-fill the octets of ``value`` that a capture cut short.

        A model parsed from a capture cut short records, in its
        ``__short_read__``, the field of :attr:`__schema__` the capture ended
        inside and the octets of it present. A padding field keeps only those
        octets, where the other fields read the rest as zeros, so a value
        read at or past the cut comes back short. Zero-filled, it rebuilds as
        the rest of the header does, and the rebuild is cut back to what was
        captured. A value of any other width is handed back for
        :meth:`_make_octets` to refuse.

        Args:
            value: the value taken from ``model``
            size: octets in the value's field
            model: the data model ``value`` was taken from
            field: the field of :attr:`__schema__` that holds ``value``
            offset: where ``value`` starts in ``field``

        Returns:
            ``value`` zero-filled to ``size`` where it is exactly the octets
            the cut kept of it; otherwise ``value`` itself.

        .. versionadded:: 1.6.0

        """
        if not isinstance(value, (bytes, bytearray)) or len(value) >= size:
            return value
        get = getattr(model, 'get', None)
        record = get('__short_read__') if callable(get) else None
        if record is None:
            return value
        name, count = record
        fields = list(cls.__schema__.__fields__)
        if name == field:
            kept = min(max(count - offset, 0), size)
        elif name in fields and field in fields and fields.index(name) < fields.index(field):
            kept = 0
        else:
            return value
        if len(value) == kept:
            return bytes(value).ljust(size, b'\x00')
        return value

    def _make_uint(self, value: 'Any', *, bits: 'int', name: 'str', alias: 'Optional[str]' = None) -> 'int':
        """Check that ``value`` is an unsigned integer that fits in ``bits`` bits.

        A :obj:`bool` passes only for a one-bit field, so that a flag given
        for a wider field is refused rather than read as ``0`` or ``1``.

        Args:
            value: the value given for the field
            bits: width of the field, in bits
            name: name of the field, for the error message
            alias: prefix of the error message, for a caller whose
                :attr:`alias` raises before ``read()`` sets it; :attr:`alias`
                by default

        Returns:
            ``value`` as a plain :class:`int`.

        Raises:
            ProtocolError: If ``value`` is not an :class:`int`, is a
                :obj:`bool` for a field wider than one bit, is negative, or
                does not fit in ``bits`` bits. The message names ``alias``.

        .. versionadded:: 1.6.0

        """
        if (not isinstance(value, int) or (isinstance(value, bool) and bits != 1)
                or not 0 <= value < (1 << bits)):
            raise ProtocolError(f'{self.alias if alias is None else alias}: invalid {name}: {value!r}')
        return int(value)

    def _make_sint(self, value: 'Any', *, bits: 'int', name: 'str', alias: 'Optional[str]' = None,
                   allow_unsigned: 'bool' = False) -> 'int':
        """Check that ``value`` is a signed integer that fits in ``bits`` bits.

        The inverse of :meth:`_read_sint`. A :obj:`bool` is refused whatever
        ``bits`` is, since no signed field holds a flag.

        Args:
            value: the value given for the field
            bits: width of the field, in bits
            name: name of the field, for the error message
            alias: prefix of the error message, for a caller whose
                :attr:`alias` raises before ``read()`` sets it or is not the
                prefix its messages carry; :attr:`alias` by default
            allow_unsigned: also accept the unsigned spelling of the field's
                ``bits`` bits, i.e. up to ``2 ** bits - 1``, for a field whose
                specification spells one value both ways, as a sentinel
                written ``-1`` and ``0xFF...F``; both denote the same bits

        Returns:
            The unsigned integer whose ``bits`` bits denote ``value`` in
            two's complement.

        Raises:
            ProtocolError: If ``value`` is not an :class:`int`, is a
                :obj:`bool`, or does not fit in ``bits`` bits as two's
                complement (or, with ``allow_unsigned``, as an unsigned
                integer either). The message names ``alias``.

        .. versionadded:: 1.6.0

        """
        bound = 1 << (bits - 1)
        limit = 2 * bound if allow_unsigned else bound
        if not isinstance(value, int) or isinstance(value, bool) or not -bound <= value < limit:
            raise ProtocolError(f'{self.alias if alias is None else alias}: invalid {name}: {value!r}')
        return value & ((1 << bits) - 1)

    @staticmethod
    def _uint_size(value: 'int', *, minimum: 'int' = 0) -> 'int':
        """Count the octets a non-negative integer needs.

        ``value.bit_length()`` is rounded up to whole octets: ``// 8`` alone
        floors, and counts one octet too few for a width that is not a
        multiple of eight.

        Args:
            value: the integer, not negative
            minimum: the fewest octets to count, for a field that cannot be
                empty although ``0`` needs none

        Returns:
            The octets ``value`` needs, and at least ``minimum``.

        .. versionadded:: 1.6.0

        """
        return max(minimum, (value.bit_length() + 7) // 8)

    @classmethod
    def _make_vector(cls, octets: 'bytes', *, size: 'int' = 1) -> 'bytes':
        """Write ``octets`` as a length-prefixed vector.

        The inverse of :meth:`_read_vector`: a ``size``-octet unsigned
        big-endian length, packed by :meth:`_make_pack`, then ``octets``.

        Args:
            octets: the vector's octets
            size: octets in the length prefix

        Returns:
            The length prefix followed by ``octets``.

        Raises:
            StructError: If the length of ``octets`` does not fit in ``size``
                octets.

        .. versionadded:: 1.6.0

        """
        return cls._make_pack(len(octets), size=size) + octets

    @classmethod
    def _make_uints(cls, values: 'Iterable[int]', *, size: 'int' = 1) -> 'bytes':
        """Write ``values`` as a run of ``size``-octet unsigned big-endian integers.

        The inverse of :meth:`_read_uints`, each value packed by
        :meth:`_make_pack`.

        Args:
            values: the integers, or anything :class:`int` converts to one,
                such as an enumeration member
            size: octets in each integer

        Returns:
            The packed integers, concatenated in order.

        Raises:
            StructError: If a value is negative, or does not fit in ``size``
                octets.

        .. versionadded:: 1.6.0

        """
        return b''.join(cls._make_pack(int(value), size=size) for value in values)

    def _make_mac_addr(self, addr: 'str | bytes | bytearray', *, size: 'Optional[int]' = 6,
                       name: 'str' = 'MAC address', alias: 'Optional[str]' = None) -> 'bytes':
        """Make a MAC address, or an EUI-64 one with ``size=8``.

        The inverse of :meth:`_read_mac_addr`.

        Args:
            addr: ``:``- or ``-``-separated *hex* encoded address
            size: octets in the address, or :data:`None` for any number of
                them, none included
            name: name of the address, for the error message
            alias: prefix of the error message, for a caller whose
                :attr:`alias` raises before ``read()`` sets it or is not the
                prefix its messages carry; :attr:`alias` by default

        Returns:
            The address octets.

        Raises:
            ProtocolError: If ``addr`` is not a :class:`str`, :class:`bytes`
                or :class:`bytearray` (a :obj:`bool` included), or is not a
                ``:``- or ``-``-separated *hex* encoded address of ``size``
                octets. The message names ``alias``.

        .. versionadded:: 1.6.0

        """
        prefix = self.alias if alias is None else alias
        if not isinstance(addr, (str, bytes, bytearray)):
            raise ProtocolError(f'{prefix}: invalid {name}: must be a str, bytes or '
                                f'bytearray, not {addr!r}')
        text = addr.encode() if isinstance(addr, str) else bytes(addr)
        octets = text.replace(b'-', b':').split(b':') if text else []
        if ((size is None or len(octets) == size)
                and all(len(octet) == 2 and all(chr(digit) in string.hexdigits for digit in octet)
                        for octet in octets)):
            return bytes.fromhex(b''.join(octets).decode())
        raise ProtocolError(f'{prefix}: invalid {name}: {addr!r}')

    def _make_index(self, value: 'Any', namespace: 'Type[_ET]', *, bits: 'int', name: 'str',
                    alias: 'Optional[str]' = None) -> '_ET':
        """Resolve the code given for an enumeration field of ``make()``.

        The field takes a member of ``namespace`` or an :class:`int` code,
        and either resolves with ``namespace``'s
        :meth:`~pcapkit.corekit.enum.EnumLookup.get`. A name is refused rather
        than looked up, so a caller holding one resolves it first, with
        :meth:`resolve_index` (:issue:`2594`). The code is checked as
        :meth:`_make_uint` checks an integer, so a :obj:`bool` passes only for
        a one-bit field (:issue:`2617`): the field's width decides what is
        refused, not the enumeration's range.

        Args:
            value: the value given for the field
            namespace: the enumeration the field holds
            bits: width of the field, in bits
            name: name of the field, for the error message
            alias: prefix of the error message, for a caller whose
                :attr:`alias` raises before ``read()`` sets it; :attr:`alias`
                by default

        Returns:
            What ``namespace``'s :meth:`~pcapkit.corekit.enum.EnumLookup.get`
            resolves ``value`` to. For most registries that includes an
            unassigned code, as the ``Unassigned`` or ``Reserved`` member their
            ``_missing_`` builds. Where ``get`` raises :exc:`ValueError` for a
            code the field carries, as a closed enumeration does, the code
            itself comes back as an :class:`int`, so that the field is rebuilt
            as captured.

        Raises:
            ProtocolError: If ``value`` is not an :class:`int` (a name among
                them), is a :obj:`bool` for a field wider than one bit, is
                negative, or does not fit in ``bits`` bits. The message names
                ``alias``.

        .. versionchanged:: 1.6.0

           Takes the enumeration and the width of the field, in place of the
           ``default``, ``namespace``, ``reversed`` and ``pack`` arguments,
           refuses a code the field cannot carry, and refuses a name rather
           than resolving it against an enumeration inferred from the calling
           method's frame (:issue:`2594`).

        """
        code = self._make_uint(value, bits=bits, name=name, alias=alias)
        try:
            return namespace.get(code)
        except ValueError:
            return cast('_ET', code)

    @classmethod
    def _make_payload(cls, data: 'Data') -> 'ProtocolBase':
        """Create payload from ``data`` for protocol construction.

        The payload's type and name are ``__next_type__`` and
        ``__next_name__``. If either is missing or :data:`None`, or ``data``
        holds nothing under ``__next_name__``, the payload is a
        :class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload`, as for
        a protocol with no next layer; otherwise :meth:`Protocol.from_data
        <pcapkit.protocols.protocol.Protocol.from_data>` builds it.

        :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` carries
        both keys, so ``data`` rebuilt from such a :obj:`dict` dispatches as
        the info did. A hand-written :obj:`dict` must carry them too, as it
        must ``__short_read__`` and, for IPv6, ``__exthdr__``: the payload is
        never guessed from the other keys of ``data`` (:issue:`2003`).

        The payload is built one layer further into the frame, as
        :meth:`_parse_next_layer` counts it, so a rebuild stops at
        :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT` where the parse did
        (:issue:`1610`). The payload's parse reports nothing, the limit
        included: this protocol's own parse goes over the same octets, so the
        rebuilt frame reports each warning, and each error a next-layer fallback
        absorbs, once, as the parsed one did (:issue:`2711`).

        Args:
            data: protocol data

        Returns:
            Payload for protocol construction.

        """
        proto = cast('Optional[Type[Protocol]]', data.get('__next_type__'))
        name = cast('Optional[str]', data.get('__next_name__'))
        if (proto is None or not (isinstance(proto, type) and issubclass(proto, ProtocolBase))
                or name is None or name not in data):
            from pcapkit.protocols.misc.no_payload.protocol import \
                NoPayload  # pylint: disable=import-outside-toplevel
            return NoPayload.from_fields()

        token, rebuilt = frame_depth.set(frame_depth.get() + 1), rebuilding.set(True)
        try:
            return proto.from_data(data[name])
        finally:
            rebuilding.reset(rebuilt)
            frame_depth.reset(token)

    @staticmethod
    def _lookup_registry(registry: 'DefaultDict[Any, _VT]', code: 'Any') -> '_VT':
        """Look up a dispatch :term:`registry` entry without recording a miss.

        Arguments:
            registry: dispatch registry to read, i.e. :attr:`self.__proto__
                <pcapkit.protocols.protocol.Protocol.__proto__>` or one of the
                per-protocol ``__option__`` / ``__chunk__`` / ``__block__``
                family. Passed in rather than read from the class, so that a
                caller reaching the registry through an instance keeps doing
                so.
            code: registry key to look up, i.e. the wire code being dispatched on

        Returns:
            The entry registered for ``code``, or the fallback ``registry``
            declares when ``code`` is not registered.

        Important:
            Each of these registries is a :class:`collections.defaultdict` on a
            *class* attribute, shared process-wide, so ``registry[code]`` would
            insert every code it misses: one packet with an unrecognised code
            would grow the registry permanently. The entry buys nothing, costs a
            spurious "already registered" warning on the next genuine
            ``register`` of that code, and makes "is this code registered?"
            depend on what has been parsed, so the fallback is read from the
            default factory directly.

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
                <pcapkit.protocols.protocol.Protocol.__proto__>`. Passed in
                rather than read from the class, so that a caller reaching the
                registry through an instance keeps doing so.
            proto: next layer protocol index

        Returns:
            The class registered for ``proto``, or the fallback ``registry``
            declares -- normally :class:`~pcapkit.protocols.misc.raw.protocol.Raw` -- when
            ``proto`` is not registered.

        Important:
            The lookup is :meth:`self._lookup_registry
            <pcapkit.protocols.protocol.Protocol._lookup_registry>`, so a miss
            does not grow the shared registry. The entry found, registered or
            the fallback, may be a
            :class:`~pcapkit.corekit.module.ModuleDescriptor`, resolved to the
            class it names.

            Nothing is written back. A hit memoised under ``proto`` would keep
            a class :func:`importlib.reload` makes stale, and make parsing
            mutate a registry the whole process shares (:issue:`1559`); so
            would a memo in the default factory or in a cache beside the
            registry (:issue:`421`, :issue:`425`, :issue:`555`). Each lookup
            resolves its descriptor again, kept cheap by
            :attr:`ModuleDescriptor.klass
            <pcapkit.corekit.module.ModuleDescriptor.klass>` reading
            :data:`sys.modules` rather than re-entering
            :func:`importlib.import_module` (:issue:`574`).

        """
        protocol = ProtocolBase._lookup_registry(registry, proto)
        if isinstance(protocol, ModuleDescriptor):
            return protocol.klass
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
            The method adds a ``__next_type__`` key to ``dict_`` to store the
            next layer protocol type, and a ``__next_name__`` key to store the
            next layer protocol name. :meth:`Info.to_dict
            <pcapkit.corekit.infoclass.Info.to_dict>` carries both, so that
            :meth:`_make_payload` dispatches a :obj:`dict` rebuild on them,
            while the dumpers and ``repr`` leave them out (:issue:`2003`).

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

        empty = self._empty_next_layer(file_, length)
        if empty is not None:
            protocol = empty
        elif self._sigterm:
            from pcapkit.protocols.misc.raw.protocol import Raw as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        else:
            protocol = self._lookup_next_layer(self.__proto__, proto)

        return self._parse_next_layer(protocol, file_, length, alias=proto, packet=packet,
                                      layer=self._exlayer, protocol=self._exproto,
                                      context=self._exctx)

    def _empty_next_layer(self, file_: 'bytes', length: 'int') -> 'Optional[Type[ProtocolBase]]':
        r"""The class a next layer with nothing to parse is kept as.

        Arguments:
            file\_: payload of the current layer
            length: valid (*non-padding*) length

        Returns:
            :data:`None` if octets were captured past the header and it leaves
            its next layer a length, which is then parsed. Otherwise
            :class:`~pcapkit.protocols.misc.raw.protocol.Raw` if no octets were
            captured past a header leaving its next layer a negative length, and
            :class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload` if
            the header leaves none, or no octets past it.

        Note:
            A header leaves a negative length when it declares more than it was
            given: one the capture cut short, read at the octets captured, or an
            IPv6 extension header overrunning the payload (:issue:`2477`). Such a
            next layer is kept raw, not dispatched on a code the cut may have
            read as zeros (:issue:`1170`). :meth:`from_data` reads the rebuild of
            a cut header at the width its parse read it at, which leaves it the
            same length, so the rebuild keeps ``Raw`` where its data model did
            (:issue:`2717`, :issue:`2761`).

        .. versionadded:: 1.6.0

        """
        if file_ and length != 0:
            return None
        if not file_ and length < 0:
            from pcapkit.protocols.misc.raw.protocol import Raw  # isort: skip # pylint: disable=import-outside-toplevel
            return Raw
        from pcapkit.protocols.misc.no_payload.protocol import NoPayload  # isort: skip # pylint: disable=import-outside-toplevel
        return NoPayload

    @staticmethod
    def _parse_next_layer(klass: 'Type[ProtocolBase]', file_: 'bytes', length: 'int', /, *,
                          layer: 'Optional[str]' = None,
                          protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                          context: 'Optional[ContextRegistry]' = None,
                          **state: 'Any') -> 'ProtocolBase':
        r"""Parse the next layer, or keep it as raw octets if its header was not captured.

        Arguments:
            klass: next layer protocol class
            file\_: payload of the current layer
            length: valid (*non-padding*) length
            layer: parse the next layer until such layer
            protocol: parse the next layer until such protocol
            context: caller supplied parsing context
            **state: next-layer state, keyed as
                :data:`~pcapkit.protocols.protocol._NEXT_LAYER_KEYWORDS`, which
                :meth:`_from_parent` hands on

        Returns:
            Instance of ``klass``, or of :class:`~pcapkit.protocols.misc.raw.protocol.Raw`
            when fewer octets were captured than its header needs, or when it is
            past :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`.

        Note:
            :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>`
            zero-fills a field the stream ends inside, so a header parsed from
            too few octets is filled with values that were never on the wire, and
            :meth:`from_data <Protocol.from_data>` rebuilds them (:issue:`1170`).
            Such a payload is kept as :class:`~pcapkit.protocols.misc.raw.protocol.Raw`
            instead, as an unparseable one is.

            The captured octets are the first ``length`` of ``file_``, or all of
            it when it holds fewer, as a truncated capture does. They are short
            of the header when there are fewer than the next layer's
            :meth:`__length_hint__
            <pcapkit.protocols.protocol.Protocol.__length_hint__>`, unless the
            header it parsed, :attr:`length
            <pcapkit.protocols.protocol.Protocol.length>` octets long, fits
            in them anyway: for a variable-length header such as
            :class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2` the hint is the longest
            form rather than the shortest. A next layer that reports no hint is
            kept as parsed.

            The warnings of a parse that may be replaced are held until that is
            known, then:

            * **replaced as short** -- dropped, since they describe a header the
              result does not have: ``packet length < 0`` twice for an Ethernet
              frame of 10 octets (:issue:`1580`);
            * **kept** -- reported as the parse ends, inside the guard that
              catches them under an ``error`` filter; a layer kept with its
              header cut short still warns;
            * **raised** -- dropped when
              :func:`~pcapkit.corekit.decorators.beholder`, which wraps
              :meth:`_import_next_layer`, replaces the layer, whose ``error``
              reports the failure (:issue:`2308`); otherwise reported as the
              error leaves.

            Under ``beholder`` a layer is held however much was captured, since
            one that raises is replaced at any length (:issue:`2516`), so a kept
            layer's warnings follow those of the layers it carries. Outside it,
            a layer captured at least as long as its hint cannot be replaced,
            and is parsed holding nothing, even inside one that holds.

            A layer past :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT` in its frame is not parsed:
            it and the rest of the frame are kept as
            :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, marked
            :attr:`_past_layer_limit`, with one
            :exc:`~pcapkit.utilities.warnings.ProtocolWarning` (:issue:`1610`).

        Warns:
            ProtocolWarning: If the next layer is past :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`.

        .. versionchanged:: 1.8.0

           The stops and the context are keyword-only, the context spelt
           ``context`` rather than ``__context__``, and every other keyword is
           next-layer state, refused unless it is one of
           :data:`~pcapkit.protocols.protocol._NEXT_LAYER_KEYWORDS` (:issue:`2840`).

        """
        stops = {'layer': layer, 'protocol': protocol, 'context': context}  # type: dict[str, Any]
        depth = frame_depth.get() + 1
        limit = config.FRAME_LAYER_LIMIT
        if limit != -1 and depth > limit:
            from pcapkit.protocols.misc.no_payload.protocol import NoPayload  # isort: skip # pylint: disable=import-outside-toplevel
            from pcapkit.protocols.misc.raw.protocol import Raw  # isort: skip # pylint: disable=import-outside-toplevel

            # NOTE: Nothing is lost if the next layer is raw already, or empty.
            if klass is not Raw and klass is not NoPayload:
                message = (f'the frame reached the limit of {limit} layers; the rest of it, '
                           f'from {klass.__name__} on, is left undissected')
                # NOTE: Inside a payload being rebuilt, the layer it is rebuilt
                # for warns of the same octets once its own parse gets here.
                if not rebuilding.get():
                    warn(message, ProtocolWarning, stacklevel=stacklevel())
                # pylint: disable-next=protected-access
                raw = Raw._from_parent(file_, length, **stops, **{**state, 'error': message})
                raw._past_layer_limit = True  # pylint: disable=protected-access
                return raw

        captured = min(length, len(file_))
        token = frame_depth.set(depth)
        try:
            # NOTE: Under ``beholder`` a layer that raises is replaced at any length,
            # so its warnings are held however much was captured (#2516).
            with hold_warnings(beholding.get() or _short_of_hint(klass, captured)) as held:
                try:
                    next_ = klass._from_parent(file_, length, **stops, **state)  # pylint: disable=protected-access
                except Exception:
                    # NOTE: Under ``beholder`` the layer is replaced and its warnings
                    # go with it; outside it, they leave with the error (#2308).
                    held.discard = beholding.get()
                    raise

                length_hint = getattr(next_, '__length_hint__', None)
                hint = None if length_hint is None else length_hint()
                held.discard = hint is not None and captured < hint and captured < next_.length
        finally:
            frame_depth.reset(token)
        if held.discard:
            from pcapkit.protocols.misc.raw.protocol import Raw  # isort: skip # pylint: disable=import-outside-toplevel
            next_ = Raw._from_parent(file_, length, **stops, **state)  # pylint: disable=protected-access
        return next_

    @classmethod
    def _analyze_from_parent(cls, proto: 'int', payload: 'bytes', /, *,
                             layer: 'Optional[str]' = None,
                             protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                             context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
                             **state: 'Any') -> 'ProtocolBase':
        """Analyse a payload with the state the layer carrying it would hand on.

        :meth:`analyze` runs as calling it runs, given the stops and the
        context set, and ``state`` travels on
        :data:`~pcapkit.protocols.protocol._analyze_state` to the
        :meth:`_analyze_next_layer` it reaches, so an override of :meth:`analyze`,
        as :meth:`Transport.analyze
        <pcapkit.protocols.transport.transport.Transport.analyze>`, hands it on as
        the base's does. A reassembled IP datagram's payload takes the datagram's
        addresses and IP version this way, as a frame's IP layer hands them to
        its next layer through :meth:`_from_parent` (:issue:`2945`).

        Arguments:
            proto: Protocol registry number.
            payload: Packet payload.
            layer: Parse the payload until such layer.
            protocol: Parse the payload until such protocol.
            context: Caller supplied parsing context.
            **state: Next-layer state, keyed as
                :data:`~pcapkit.protocols.protocol._NEXT_LAYER_KEYWORDS`.

        Returns:
            Parsed payload, as :meth:`analyze` returns it.

        Raises:
            UnsupportedCall: If a key of ``state`` is not next-layer state, as
                for :meth:`_from_parent`.

        .. versionadded:: 1.8.0

        """
        if not _NEXT_LAYER_KEYWORDS.issuperset(state):
            unknown = sorted(set(state) - _NEXT_LAYER_KEYWORDS)
            raise UnsupportedCall(f'{cls.__name__}: unknown next-layer state: '
                                  f'{", ".join(map(repr, unknown))}')

        # NOTE: Only the stops set, so ``analyze`` is called as a caller giving none would call it.
        stops = {name: value for name, value in (('layer', layer), ('protocol', protocol), ('context', context))
                 if value is not None}  # type: dict[str, Any]
        token = _analyze_state.set(state)
        try:
            return cls.analyze(proto, payload, **stops)
        finally:
            _analyze_state.reset(token)

    @staticmethod
    def _analyze_next_layer(klass: 'Type[ProtocolBase]', payload: 'bytes', code: 'Any', /, *,
                            layer: 'Optional[str]' = None,
                            protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                            context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
                            **state: 'Any') -> 'ProtocolBase':
        """Parse a payload :meth:`analyze` dispatched, or keep it as raw octets if it fails.

        Arguments:
            klass: protocol class the payload was dispatched to
            payload: payload to parse
            code: code the payload was dispatched on, the ``alias`` of the parse
                and its fallback unless ``state`` gives one, as a frame's next
                layer takes it
            layer: parse the payload until such layer
            protocol: parse the payload until such protocol
            context: caller supplied parsing context
            **state: next-layer state, keyed as
                :data:`~pcapkit.protocols.protocol._NEXT_LAYER_KEYWORDS`, which
                that :meth:`_analyze_from_parent` hands on through
                :data:`~pcapkit.protocols.protocol._analyze_state` joins

        Returns:
            Instance of ``klass``. A payload that fails to parse is kept as
            :class:`~pcapkit.protocols.misc.raw.protocol.Raw` holding all of it,
            its ``error`` the failure's message and its ``protocol`` ``code``,
            as a frame's fallback is, or as
            :class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload` after
            an end-of-file :exc:`~pcapkit.utilities.exceptions.StructError`. An
            empty payload is :class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload`
            unparsed.

        Note:
            The parse runs on trial, as under
            :func:`~pcapkit.corekit.decorators.beholder`. A
            :exc:`~pcapkit.utilities.exceptions.ProtocolError` built during it is
            quiet, so the refusal the fallback records logs nothing and installs no
            exception hook (:issue:`2588`). Any other error is as loud as it was
            constructed, and is logged here at :data:`logging.WARNING` as well, as
            :func:`~pcapkit.corekit.decorators.beholder` logs it, with its traceback
            in verbose mode. A parse that raises is dropped with its warnings
            (:issue:`2308`), and a parse kept reports its own after those of the
            layers it carries, as a frame's layer does. The fallback is built after
            the trial ends, so an error it raises is loud.

            An empty payload is kept as a frame keeps an empty next layer (see
            :meth:`_empty_next_layer`): parsed on its own, ``klass`` would read
            a header cut before its first octet, made of nothing but zeros
            (:issue:`2880`).

            The trial and a layer kept instead are built by :meth:`_from_parent`,
            from the stops, the context and ``state`` (:issue:`2840`), so an
            enclosing IP version never picks a family base's member
            (:issue:`2945`).

        """
        # NOTE: ``_analyze_from_parent``'s state joins, for this payload alone: none is left for a
        # parse inside it, and ``_analyze_from_parent`` restores the variable after (#2945).
        state = {**(_analyze_state.get() or {}), **state}
        _analyze_state.set(None)
        # NOTE: The parse takes ``alias`` as a frame's next layer does, its fallback too (#2933).
        state.setdefault('alias', code)
        stops = {'layer': layer, 'protocol': protocol, 'context': context}  # type: dict[str, Any]

        payload_io = io.BytesIO(payload)
        # NOTE: No octets are no layer, as a frame's ``_empty_next_layer`` keeps them (#2880).
        if not payload:
            from pcapkit.protocols.misc.no_payload.protocol import NoPayload  # isort: skip # pylint: disable=import-outside-toplevel
            return NoPayload._from_parent(payload_io, 0, **stops, **state)  # pylint: disable=protected-access
        eof, error = False, ''
        # NOTE: ``beholding`` as well, so a trial block inside the parse, as TLS's, drops its
        # warnings on a raise rather than reporting them past this one (#2308).
        token = beholding.set(True)
        try:
            with hold_warnings() as held:
                try:
                    with CaughtByCaller(ProtocolError):
                        return klass._from_parent(payload_io, len(payload), **stops, **state)  # pylint: disable=protected-access
                except Exception:
                    held.discard = True
                    raise
        except Exception as exc:
            eof, error = isinstance(exc, StructError) and exc.eof, str(exc)  # pylint: disable=no-member
            # NOTE: Keyed on the class, as ``beholder`` keys it: a refusal is quiet (#2588), and
            # any other error, a quiet end-of-file StructError included, is logged at WARNING.
            if not isinstance(exc, ProtocolError):
                logger.warning(error, stack_info=DEVMODE, stacklevel=stacklevel())

                if VERBOSE:
                    logger.error('The following error occurred while parsing the packet:')
                    traceback.print_exc()
        finally:
            beholding.reset(token)

        if TYPE_CHECKING:
            fallback: 'Type[ProtocolBase]'
        if eof:
            from pcapkit.protocols.misc.no_payload.protocol import NoPayload as fallback  # pylint: disable=import-outside-toplevel # isort: skip
        else:
            from pcapkit.protocols.misc.raw.protocol import Raw as fallback  # pylint: disable=import-outside-toplevel # isort: skip

        # NOTE: Rewound, as the failed parse read the stream; ``error`` as ``beholder``
        # gives a frame's fallback (#2842, #2862).
        payload_io.seek(0)
        state['error'] = error
        return fallback._from_parent(payload_io, len(payload), **stops, **state)  # pylint: disable=protected-access

    @classmethod
    def _from_parent(cls, file: 'IO[bytes] | bytes', length: 'Optional[int]',
                     extra: 'Optional[Mapping[str, Any]]' = None, /, *,
                     layer: 'Optional[str]' = None,
                     protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                     context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
                     **state: 'Any') -> 'Self':
        """Parse a layer with the state the layer carrying it hands on.

        :meth:`__new__` and then :meth:`__init__` run as calling the class runs
        them, given the stops, the context and ``extra`` alone. ``state`` travels on
        :attr:`__next_layer__` and reaches only the hooks from
        :meth:`__post_init__` on, so the enclosing IP version it may carry
        never picks a family base's member (:issue:`2840`).

        Args:
            file: Source packet stream.
            length: Length of packet data.
            extra: Other keywords for :meth:`__init__`, those a class's own
                parse takes, such as the ``num``, ``sct`` and ``ctx`` of
                :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG`.
            layer: Parse packet until such layer.
            protocol: Parse packet until such protocol.
            context: Caller supplied parsing context.
            **state: Next-layer state, keyed as
                :data:`~pcapkit.protocols.protocol._NEXT_LAYER_KEYWORDS`.

        Returns:
            The parsed layer; for a family base, the member it picks.

        Raises:
            UnsupportedCall: If a key of ``state`` is not next-layer state, a
                defect of the caller rather than of the octets.

        .. versionadded:: 1.8.0

        """
        if not _NEXT_LAYER_KEYWORDS.issuperset(state):
            unknown = sorted(set(state) - _NEXT_LAYER_KEYWORDS)
            raise UnsupportedCall(f'{cls.__name__}: unknown next-layer state: '
                                  f'{", ".join(map(repr, unknown))}')

        keywords = {**(extra or {}), 'layer': layer, 'protocol': protocol, 'context': context}
        made = cast('object', cls.__new__(cls, file, length, **keywords))
        if not isinstance(made, cls):
            return cast('Self', made)
        made.__next_layer__ = state
        try:
            made.__init__(file, length, **keywords)  # type: ignore[misc]
        finally:
            # NOTE: Left behind by an ``__init__`` override that never reaches the base's.
            made.__dict__.pop('__next_layer__', None)
        return made

    @staticmethod
    def _next_layer_state(keywords: 'Mapping[str, Any]') -> 'dict[str, Any]':
        """The next-layer state among the keywords a layer is parsed with.

        A layer that re-dispatches its own octets to another class, as TLS's
        SSLv2 trial and an HTTP subclass's versioned parse do, hands it on
        through :meth:`_from_parent`. No hook of those classes reads the other
        keywords.

        Args:
            keywords: Keywords of the layer's parse.

        Returns:
            Those keyed as :data:`~pcapkit.protocols.protocol._NEXT_LAYER_KEYWORDS`.

        .. versionadded:: 1.8.0

        """
        return {key: value for key, value in keywords.items() if key in _NEXT_LAYER_KEYWORDS}

    def _check_term_threshold(self) -> bool:
        """Check if reached termination threshold."""
        return self._meets_term_threshold(self._exlayer, self._exproto)

    @classmethod
    def _meets_term_threshold(cls, layer: 'Optional[str]',
                              protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]') -> 'bool':
        """Whether a parse stopping at ``layer`` or ``protocol`` stops at this class.

        Arguments:
            layer: layer to parse until, matched case-insensitively
            protocol: protocol to parse until, by name, class or instance

        Returns:
            Whether this class is in ``layer`` or is ``protocol``, which keeps its
            next layer as :class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

        .. versionadded:: 1.7.0

        """
        if layer is None or (own := cls.__layer__) is None:
            layer_match = False
        else:
            layer_match = own.upper() == layer.upper()

        if protocol is None:
            protocol_match = False
        else:
            protocol_match = False
            comp_test = [name.upper() for name in cls.id()]
            for test in cls.expand_comp(protocol):
                if test in comp_test:
                    protocol_match = True
                    break

        return layer_match or protocol_match

    @classmethod
    def _stops_next_layer(cls, kwargs: 'dict[str, Any]') -> 'bool':
        """Whether a parse given ``kwargs`` stops at this class, as ``_sigterm`` stops a layer.

        Arguments:
            kwargs: the stops of the parse, its ``layer`` and ``protocol``

        Returns:
            Whether :meth:`analyze` keeps the payload as
            :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, as a frame keeps the
            next layer of the layer it stops at.

        .. versionadded:: 1.7.0

        .. versionchanged:: 1.8.0

           Reads ``layer`` and ``protocol`` alone, and :obj:`None` is the only no
           stop, as for :meth:`__init__` (:issue:`2840`).

        """
        return cls._meets_term_threshold(kwargs.get('layer'), kwargs.get('protocol'))

    @classmethod
    def _analyze_stop(cls, layer: 'Optional[str]',
                      protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]') -> 'Optional[Type[ProtocolBase]]':
        """Check the stops an ``analyze`` is given, and whether its payload is past one.

        Arguments:
            layer: layer to parse until
            protocol: protocol to parse until

        Returns:
            :class:`~pcapkit.protocols.misc.raw.protocol.Raw` where a stop meets this
            class, as :meth:`_stops_next_layer` tells, which keeps the payload raw;
            otherwise :obj:`None`.

        Raises:
            FormatError: If ``layer`` names no layer.
            RegistryError: If ``protocol`` is no protocol name, class or instance.

        .. versionadded:: 1.8.0

        """
        cls._check_stops(layer, protocol)
        if not cls._stops_next_layer({'layer': layer, 'protocol': protocol}):
            return None
        from pcapkit.protocols.misc.raw.protocol import Raw  # isort: skip # pylint: disable=import-outside-toplevel
        return Raw

    @staticmethod
    def _check_stops(layer: 'Any', protocol: 'Any') -> 'None':
        """Check the stops a parse is given.

        Arguments:
            layer: layer to parse until: :obj:`None`, or ``'link'``,
                ``'internet'``, ``'transport'`` or ``'application'`` in any case
            protocol: protocol to parse until: :obj:`None`, or a protocol name,
                class or instance; a name is not looked up, since a stop may
                match an ``id()`` name no registry key spells, such as
                ``'HTTP/2'``

        Raises:
            FormatError: If ``layer`` is anything else.
            RegistryError: If ``protocol`` is anything else.

        .. versionadded:: 1.8.0

        """
        if layer is not None and not (isinstance(layer, str) and layer.lower() in _LAYERS):
            raise FormatError(f'unknown layer: {layer!r}; expected one of {", ".join(map(repr, _LAYERS))}')
        if protocol is not None and not (
                isinstance(protocol, (str, ProtocolBase))
                or (isinstance(protocol, type) and issubclass(protocol, ProtocolBase))):
            raise RegistryError(f'unknown protocol: {protocol!r}; expected a protocol name, '
                                'class or instance')

    def _read_qs_rate(self, code: 'int') -> 'int':
        """Read a Quick-Start rate code as a rate in kbps.

        :rfc:`4782#section-3.1` encodes the Rate Request, and the Rate Report
        formatted exactly as it, as a four-bit ``N`` that stands for
        ``K * 2 ** N`` bps with ``K`` set to 40,000, and ``N = 0`` for a rate of
        zero. The IPv6 option keeps the IPv4 format (:rfc:`4782#section-3.2`),
        and the TCP Quick-Start Response formats its Rate Request the same way
        (:rfc:`4782#section-4.2`).

        Args:
            code: the four-bit rate field, ``N``

        Returns:
            The rate in kbps: ``0`` for ``N = 0``, else ``40 * 2 ** N``.

        .. versionadded:: 1.6.0

        """
        return 40 * 2 ** code if code else 0

    def _make_qs_rate(self, rate: 'Any') -> 'int':
        """Make the Quick-Start rate code for a rate in kbps.

        The inverse of :meth:`_read_qs_rate`. A rate between two codes is
        rounded down to the lower one, so the option never carries more than
        the rate given.

        Args:
            rate: the rate, in kbps

        Returns:
            The four-bit rate field, ``N``.

        Raises:
            ProtocolError: If ``rate`` is not an :class:`int`, is a
                :obj:`bool`, or is one the field cannot carry: negative, above
                zero but below the 80 kbps of ``N = 1``, or at or above the
                ``40 * 2 ** 16`` kbps that needs a fifth bit. The message names
                :attr:`alias`.

        .. versionadded:: 1.6.0

        """
        if (not isinstance(rate, int) or isinstance(rate, bool)
                or (rate and not 80 <= rate < 40 * 2 ** 16)):
            raise ProtocolError(f'{self.alias}: invalid Quick-Start rate: {rate!r}')
        return (rate // 40).bit_length() - 1 if rate else 0

    def _read_float_code(self, code: 'int', *, bits: 'int') -> 'int':
        """Read an IGMPv3 or MLDv2 floating-point code as the value it encodes.

        A code below ``2 ** (bits - 1)`` is the value itself. At or above it, the
        code is ``1``, a three-bit ``exp`` and a ``bits - 4``-bit ``mant``, standing
        for ``(mant | 2 ** (bits - 4)) << (exp + 3)``: the eight-bit Max Resp Code and
        QQIC of IGMPv3 (:rfc:`3376#section-4.1.1`, :rfc:`3376#section-4.1.7`) and
        QQIC of MLDv2 (:rfc:`9777#section-5.1.9`), and the 16-bit Maximum Response
        Code of MLDv2 (:rfc:`9777#section-5.1.3`).

        Args:
            code: the code, as on the wire
            bits: the code's width, 8 or 16

        Returns:
            The value the code encodes.

        .. versionadded:: 1.7.0

        """
        if code < 1 << (bits - 1):
            return code
        width = bits - 4
        exp = (code >> width) & 0x07
        mant = code & ((1 << width) - 1)
        return (mant | (1 << width)) << (exp + 3)

    def _make_float_code(self, value: 'Any', *, bits: 'int', name: 'str') -> 'int':
        """Make the IGMPv3 or MLDv2 floating-point code for a value.

        The inverse of :meth:`_read_float_code`. A value below ``2 ** (bits - 1)``
        is its own code. Above it, the smallest exponent whose mantissa fits is
        taken, so a value the format can carry reads back exactly, and any other
        floors to the nearest one it can, the largest above them all.

        Args:
            value: the value, in the units the code stands for
            bits: the code's width, 8 or 16
            name: the field, named in an error message

        Returns:
            The code.

        Raises:
            ProtocolError: If ``value`` is not an :class:`int`, is a :obj:`bool`,
                or is negative. The message names :attr:`alias`.

        .. versionadded:: 1.7.0

        """
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ProtocolError(f'{self.alias}: invalid {name}: {value!r}')
        if value < 1 << (bits - 1):
            return value

        width = bits - 4
        limit = (1 << (width + 1)) - 1
        exp = 0
        mant = value >> 3
        while mant > limit and exp < 7:
            exp += 1
            mant = value >> (exp + 3)
        mant = min(mant, limit)
        return (1 << (bits - 1)) | (exp << width) | (mant & ((1 << width) - 1))


class Protocol(ProtocolBase, Generic[_PT, _ST]):
    """User-facing abstract base class for third-party protocols.

    Inherit it directly only to create a new protocol stack; a new protocol in
    an existing layer subclasses that layer's base class instead; see
    :doc:`/ext`. The built-in protocol families do not derive from this class
    but from :class:`ProtocolBase`, whose metaclass is :class:`ProtocolMeta`.

    .. versionchanged:: 1.3.0

       The built-in protocol families derive from :class:`ProtocolBase`, so a
       built-in protocol is not an instance of this class, where every one
       was; and a subclass is registered in ``pcapkit.protocols.__proto__``
       when it is defined.

    """

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

        Sets :attr:`self.__schema__ <pcapkit.protocols.protocol.Protocol.__schema__>`
        and :attr:`self.__data__ <pcapkit.protocols.protocol.Protocol.__data__>`
        on the subclass through :meth:`ProtocolBase.__init_subclass__`, which
        also finds an omitted one.

        Once that has accepted ``code``, a concrete subclass is also named in
        the by-name registry, :attr:`ProtocolBase.__registry__
        <pcapkit.protocols.protocol.ProtocolBase.__registry__>`, under its
        upper-cased class name; unlike ``code``'s dispatch registration, this
        is not opt-in. An abstract subclass, as
        :func:`~pcapkit.utilities.inspect.isabstract` reports it, is not named,
        nor is a class deriving :class:`ProtocolBase` alone, as every built-in
        protocol does. A name holding another entry keeps it, with a
        :exc:`~pcapkit.utilities.warnings.RegistryWarning`; only
        :meth:`ProtocolBase.register_protocol
        <pcapkit.protocols.protocol.ProtocolBase.register_protocol>` replaces
        one. The :class:`~pcapkit.corekit.module.ModuleDescriptor` naming the
        class's own module and name is no clash, and stays.

        See Also:
            For more information on the registry, please refer to
            :meth:`ProtocolBase.register_protocol <pcapkit.protocols.protocol.ProtocolBase.register_protocol>`.

        .. versionchanged:: 1.6.0

           An abstract subclass is not registered, and a name already holding
           an entry keeps it, where every subclass was registered over it
           (:issue:`2763`).

        """
        super().__init_subclass__(schema, data, code, *args, **kwargs)

        # NOTE: #2763: registered after ``code`` is accepted, never over a held name or this class's
        # own descriptor. #2784: not inspect.isabstract, whose __flags__ read GraalPy freezes early.
        if not isabstract(cls):
            name = cls.__name__.upper()
            incumbent = ProtocolBase.__registry__.setdefault(name, cls)
            if incumbent is not cls and not (isinstance(incumbent, ModuleDescriptor)
                                             and incumbent == (cls.__module__, cls.__name__)):
                incumbent_repr, protocol_repr = repr(incumbent), repr(cls)
                if incumbent_repr == protocol_repr:  # #710: tell same-named classes apart
                    incumbent_repr = f'{incumbent_repr} (id={id(incumbent):#x})'
                    protocol_repr = f'{protocol_repr} (id={id(cls):#x})'
                warn(f'protocol {name} already registered, keeping {incumbent_repr} '
                     f'over {protocol_repr}', RegistryWarning)
