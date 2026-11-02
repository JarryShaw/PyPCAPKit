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
   its header is kept as :class:`~pcapkit.protocols.misc.raw.Raw`, where it
   was parsed with zero-filled fields (:issue:`1170`).

"""
import abc
import ast
import collections
import collections.abc
import contextlib
import copy
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
import types
import urllib.parse
from typing import TYPE_CHECKING, Any, Generic, Optional, Type, TypeVar, cast, overload

import aenum

from pcapkit.corekit.context import ContextRegistry
from pcapkit.corekit.decorators import beholder, seekset
from pcapkit.corekit.fields.misc import ConditionalField, SchemaField, SwitchField
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.corekit.sentinels import ABSENT
from pcapkit.protocols import data as data_module
from pcapkit.protocols import schema as schema_module
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.misc.raw import Raw as Data_Raw
from pcapkit.protocols.data.protocol import Packet as Data_Packet
from pcapkit.protocols.schema.misc.raw import Raw as Schema_Raw
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities import config
from pcapkit.utilities.chardet import detect
from pcapkit.utilities.compat import cached_property
from pcapkit.utilities.contextvars import beholding, frame_depth, rebuilding
from pcapkit.utilities.exceptions import (BaseError, ProtocolError, ProtocolNotFound,
                                          ProtocolNotImplemented, RegistryError, StructError,
                                          UnsupportedCall, stacklevel)
from pcapkit.utilities.warnings import (ProtocolWarning, RegistryWarning, UnknownFieldWarning,
                                        hold_warnings, warn)

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from types import FrameType
    from typing import IO, Any, Callable, DefaultDict, Iterable, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal, Self

    from pcapkit.corekit.context import ProtocolContext

__all__ = ['Protocol', 'ProtocolBase']

_PT = TypeVar('_PT', bound='Data')
_ST = TypeVar('_ST', bound='Schema')
_CTX = TypeVar('_CTX', bound='ProtocolContext')
_VT = TypeVar('_VT')

# readable characters' order list
readable = [ord(char) for char in filter(lambda char: not char.isspace(), string.printable)]


@functools.lru_cache(maxsize=None)
def _make_index_calls(func: 'Callable[..., Any]') -> 'tuple[tuple[int, int, str], ...]':
    """Locate the ``_make_index`` calls in the source of ``func``.

    Args:
        func: method calling ``_make_index``

    Returns:
        One ``(first_line, last_line, argument)`` triple per call whose first
        argument is a plain name, with absolute line numbers. Empty if the
        source of ``func`` is unavailable.

    """
    try:
        lines, start = inspect.getsourcelines(func)
        tree = ast.parse(textwrap.dedent(''.join(lines)))
    except (OSError, TypeError, SyntaxError):
        return ()
    # NOTE: ``ast.parse`` always sets ``end_lineno`` on a call.
    return tuple(
        (node.lineno + start - 1,
         cast('int', node.end_lineno) + start - 1,
         node.args[0].id)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == '_make_index' and node.args and isinstance(node.args[0], ast.Name)
    )


def _passes_raw(value: 'Any', nested: 'bool' = False) -> 'bool':
    """Tell if ``make()`` keywords may carry a raw :obj:`bytes` item.

    Args:
        value: keyword arguments of ``make()``, or a value within them
        nested: if ``value`` sits inside a container

    Returns:
        :data:`True` if :obj:`bytes` sits anywhere inside a :obj:`list`,
        :obj:`tuple` or :obj:`dict` among ``value``, or a
        :class:`~pcapkit.protocols.schema.schema.Schema` does anywhere. A
        top-level :obj:`bytes` keyword (e.g. a payload) does not count.

    """
    if isinstance(value, bytes):
        return nested
    if isinstance(value, Schema):  # a ready-made item, which ``make()`` may pack into raw octets
        return True
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
        :obj:`bytes` and ``parsed`` a :class:`~pcapkit.protocols.schema.schema.Schema`.

    """
    if isinstance(made, bytes):
        return isinstance(parsed, Schema)
    if isinstance(made, (list, tuple)) and isinstance(parsed, (list, tuple)):
        return any(_raw_where_parsed(item, other) for item, other in zip(made, parsed))
    if isinstance(made, Schema) and isinstance(parsed, Schema):
        return any(_raw_where_parsed(made.get(name), parsed.get(name))
                   for name in made.__fields__ if name in parsed.__fields__)
    return False

#: Keywords that configure the construction rather than naming a field, and are
#: therefore consumed by :meth:`Protocol.__init__
#: <pcapkit.protocols.protocol.Protocol.__init__>` or by the schema layer
#: instead of by a :meth:`make <pcapkit.protocols.protocol.Protocol.make>`. No
#: signature declares them, so :func:`_declared_keywords` cannot find them and
#: they are listed here.
#:
#: ``packet`` is here because the library puts it there itself:
#: :meth:`Protocol.__init__ <pcapkit.protocols.protocol.Protocol.__init__>`
#: injects ``packet=self.packet.payload`` into every parsed ``_info``, so the
#: default :meth:`Protocol._make_data
#: <pcapkit.protocols.protocol.Protocol._make_data>` (``data.to_dict()``)
#: carries it into the keywords that :meth:`Protocol.from_data
#: <pcapkit.protocols.protocol.Protocol.from_data>` reconstructs from.
#: Refusing it would make ``from_data`` fail on any protocol whose ``make`` does
#: not declare a ``packet``, starting with
#: :class:`~pcapkit.protocols.misc.null.NoPayload`, the innermost layer of every
#: packet. It is also a real field name for some protocols --
#: :meth:`HIP.make <pcapkit.protocols.internet.hip.HIP.make>` takes the HIP
#: packet *type* under it -- and listing it here does not change how it binds,
#: only that it is never refused.
OUT_OF_BAND_KEYWORDS = frozenset({'_layer', '_protocol', '__context__',
                                  '__packet__', 'packet'})


#: Cache for :func:`_declared_keywords`, keyed by protocol class. Signatures do
#: not change after the class is created and the walk below is
#: :math:`O(\\text{MRO} \\times \\text{methods})`, so it runs once per class
#: rather than once per constructed packet.
_DECLARED_KEYWORDS = {}  # type: dict[type, Optional[frozenset[str]]]

#: Methods a construction keyword may be destined for. The keywords handed to
#: :class:`Protocol` reach all of them: :meth:`Protocol.__post_init__
#: <pcapkit.protocols.protocol.Protocol.__post_init__>` passes the same
#: ``**kwargs`` to :meth:`pack <pcapkit.protocols.protocol.Protocol.pack>` (and
#: through it to ``make``) *and* to :meth:`unpack
#: <pcapkit.protocols.protocol.Protocol.unpack>` (and through it to ``read``).
_KEYWORD_CONSUMERS = ('make', 'read', 'pack', 'unpack', '__post_init__', '__init__')


def _declared_keywords(cls: 'type') -> 'Optional[frozenset[str]]':
    """Collect every keyword the protocol ``cls`` declares a parameter for.

    Args:
        cls: Protocol class to inspect.

    Returns:
        Names of every keyword-acceptable parameter declared by any of
        :data:`_KEYWORD_CONSUMERS` anywhere in the MRO of ``cls``, plus every
        entry of :attr:`Protocol.__keywords__
        <pcapkit.protocols.protocol.Protocol.__keywords__>` found there,
        plus :data:`OUT_OF_BAND_KEYWORDS`. :obj:`None` if ``cls`` *itself* sets
        ``__keywords__`` to :obj:`None`, meaning its keywords cannot be enumerated
        and are not to be checked -- inherited :obj:`None` does not count, as
        :attr:`Protocol.__keywords__
        <pcapkit.protocols.protocol.Protocol.__keywords__>` explains.

    The union is deliberately wider than the signature of ``cls.make``, because
    a keyword reaching ``make`` is not necessarily *for* ``make``:
    :meth:`Protocol.__post_init__
    <pcapkit.protocols.protocol.Protocol.__post_init__>` hands one
    ``**kwargs`` to both the construction and the parse of the packet it has just
    constructed, so a keyword declared by ``read`` travels through ``make`` too.
    :class:`~pcapkit.protocols.internet.hip.HIP` is the live example:
    :meth:`HIP.read <pcapkit.protocols.internet.hip.HIP.read>` declares
    ``extension``, :meth:`HIP.make <pcapkit.protocols.internet.hip.HIP.make>`
    does not, and :meth:`HIP.__post_init__
    <pcapkit.protocols.internet.hip.HIP.__post_init__>` forwards it to both.

    The walk covers the whole MRO rather than the most derived override of each
    method, so that a subclass declaring its own keyword and forwarding the rest
    to its parent does not make the parent's keywords unreachable. The one
    exception is a class that sets :attr:`Protocol.__own_make_keywords__
    <pcapkit.protocols.protocol.Protocol.__own_make_keywords__>`: its
    ``make`` counts only while it is the ``make`` of ``cls``, not once a
    subclass overrides it (:issue:`2286`).

    """
    try:
        return _DECLARED_KEYWORDS[cls]
    except KeyError:
        pass

    unchecked = False
    names = set(OUT_OF_BAND_KEYWORDS)
    # NOTE: The class whose ``make`` is the one ``cls`` resolves to; any other
    # ``make`` in the MRO has been overridden.
    make_owner = next((klass for klass in cls.__mro__ if 'make' in klass.__dict__), None)
    for klass in cls.__mro__:
        # NOTE: A keyword read out of ``**kwargs`` by name is invisible to
        # :func:`inspect.signature`, so the class lists it in ``__keywords__``.
        # Read per class in the MRO, like the methods, so a subclass need not
        # repeat its parents' entries.
        keywords = klass.__dict__.get('__keywords__', ABSENT)
        if keywords is None:
            # NOTE: The :obj:`None` opt-out is *not* inherited, unlike a set,
            # which is unioned down the MRO. It describes how the class that
            # declares it dispatches, not a property its subclasses share:
            # :class:`~pcapkit.protocols.application.http.HTTP` cannot enumerate
            # its keywords because it forwards them to whichever of
            # :class:`HTTPv1 <pcapkit.protocols.application.httpv1.HTTPv1>` and
            # :class:`HTTPv2 <pcapkit.protocols.application.httpv2.HTTPv2>` the
            # ``version`` names, but each of those declares its own in full, and
            # inheriting the opt-out would exempt the very classes that can be
            # checked. A subclass that dispatches in turn says so itself.
            if klass is cls:
                unchecked = True
        elif keywords is not ABSENT:
            names.update(keywords)

        for method in _KEYWORD_CONSUMERS:
            # NOTE: Read from ``__dict__`` rather than with :func:`getattr`, so
            # that each class in the MRO contributes its *own* definition instead
            # of the most derived one every time. An ``@overload`` stub is
            # overwritten by the implementation that follows it, which is what
            # lands here.
            func = klass.__dict__.get(method)
            if func is None:
                continue

            # NOTE: A ``make`` whose keywords its class keeps to itself is read
            # only while it is the one ``cls`` uses. Read from ``__dict__`` so
            # the marker, like the :obj:`None` opt-out above, is not inherited.
            if (method == 'make' and klass is not make_owner
                    and klass.__dict__.get('__own_make_keywords__', False)):
                continue

            try:
                signature = inspect.signature(func)
            except (TypeError, ValueError):  # pragma: no cover
                # NOTE: An unintrospectable callable is skipped rather than fatal:
                # failing to widen the accepted set is a false rejection, so keep
                # walking.
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
        kwargs: Construction keywords to check, the out-of-band ones left out.
            :meth:`Protocol.__init__
            <pcapkit.protocols.protocol.Protocol.__init__>` passes those
            remaining after it has consumed them; :meth:`Protocol.from_data
            <pcapkit.protocols.protocol.Protocol.from_data>` passes its
            caller's own, less ``_layer``, ``_protocol`` and ``__context__``,
            before :meth:`Protocol._make_data
            <pcapkit.protocols.protocol.Protocol._make_data>` adds to them.
        strict: Whether an unexpected keyword is an error. :data:`True` for a
            caller's own construction; :data:`False` when the keywords were
            generated by :meth:`Protocol._make_data
            <pcapkit.protocols.protocol.Protocol._make_data>` rather than
            written by anybody -- see :meth:`Protocol.from_data
            <pcapkit.protocols.protocol.Protocol.from_data>`.

    Raises:
        UnsupportedCall: If ``strict`` and any keyword is not among those
            :func:`_declared_keywords` collects for ``cls``.

    Warns:
        UnknownFieldWarning: The same finding when not ``strict``.

    """
    declared = _declared_keywords(cls)
    if declared is None:
        return

    unexpected = sorted(key for key in kwargs if key not in declared)
    if not unexpected:
        return

    # NOTE: The check exists to catch misspellings, so name the neighbour that
    # was probably meant (``seq`` for ``seq_no``, ``ack_flag`` for ``ack``, both
    # a :func:`difflib.get_close_matches` hit); the message is the only place the
    # caller looks before reading the signature.
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
    # it cannot fix it. Raising would turn every such mismatch into a broken
    # ``from_data``, where the field is merely dropped; the warning makes that
    # audible instead.
    #
    # No explicit ``stacklevel``: the default blames the innermost frame outside
    # :mod:`pcapkit`, which is the ``from_data`` call the reader wants to be
    # pointed at, and it stays right if the frames between change, where a
    # hardcoded count would not. It is also what :meth:`Schema.__update__
    # <pcapkit.protocols.schema.schema.Schema.__update__>` passes for the
    # warning this one is the counterpart of.
    warn(f'{cls.__name__}._make_data returned keyword(s) that no signature of '
         f'{cls.__name__} declares, so they are discarded: {listed}',
         UnknownFieldWarning)


def _short_of_hint(klass: 'Type[ProtocolBase]', captured: 'int') -> 'bool':
    """Tell whether ``captured`` octets may be too few for a ``klass`` header.

    Args:
        klass: Next layer protocol class.
        captured: Octets captured for it.

    Returns:
        Whether a next layer of ``klass`` parsed from ``captured`` octets may be
        replaced with :class:`~pcapkit.protocols.misc.raw.Raw` by
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


class ProtocolMeta(abc.ABCMeta):
    """Metaclass of :class:`ProtocolBase`, and so of every protocol class.

    It adds no behaviour of its own over :class:`abc.ABCMeta`.

    """


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

    #: Protocol index mapping for decoding the next layer; see
    #: :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: and :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    #: Each value is a :class:`~pcapkit.corekit.module.ModuleDescriptor` naming the
    #: module and class, or a :class:`ProtocolBase` subclass.
    __proto__: 'DefaultDict[int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]' = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
    )

    #: Read-only copy of :attr:`__proto__` as the class defining it shipped it,
    #: taken by :meth:`__init_subclass__` before anything can register into it.
    #: :meth:`_next_layer_entry` reads it to tell a descriptor handed back from
    #: a new one without resolving it (:issue:`1504`).
    _shipped_proto: 'types.MappingProxyType[Any, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]' = \
        types.MappingProxyType({})

    #: Construction keywords this protocol consumes out of ``**kwargs`` instead
    #: of declaring as a parameter, e.g. with ``kwargs.get('spam')`` in
    #: :meth:`read` -- as :meth:`ESP.read <pcapkit.protocols.internet.esp.ESP.read>`
    #: does with ``packet``.
    #: :func:`_declared_keywords` finds keywords by
    #: reading signatures, which cannot see such a name, so a protocol that
    #: consumes one names it here and the construction check of :meth:`__init__`
    #: accepts it. The union over the MRO is used, so a subclass need not repeat
    #: its parents' entries.
    #:
    #: Declaring the parameter is preferable where possible, since that also
    #: documents the keyword to the caller and to :mod:`inspect`. This is for the
    #: cases where it is not -- a keyword handled uniformly for a whole family of
    #: names, say. It is opt-in per class, so it can only exempt a name whose
    #: author wrote it down (:issue:`617`).
    #:
    #: :obj:`None` means the keywords cannot be enumerated and the check is
    #: skipped for this protocol. That is for a *dispatcher*, whose real signature
    #: belongs to a class chosen at call time:
    #: :meth:`HTTP.make <pcapkit.protocols.application.http.HTTP.make>` declares
    #: only ``version`` and forwards everything else to
    #: :meth:`HTTPv1.make <pcapkit.protocols.application.httpv1.HTTPv1.make>` or
    #: :meth:`HTTPv2.make <pcapkit.protocols.application.httpv2.HTTPv2.make>`
    #: depending on that value, so no set of names is right for it. Use it only
    #: for that shape, since a protocol that skips the check silently discards an
    #: unknown keyword. Unlike a set, the :obj:`None` is **not** inherited: a
    #: subclass of a dispatcher is checked normally unless it dispatches too and
    #: says so, because ``HTTPv1`` and ``HTTPv2`` declare their keywords in full
    #: and exempting them along with their base would forgo the check on the very
    #: classes that can have it.
    __keywords__: 'Optional[frozenset[str]]' = frozenset()

    #: Whether the parameters of this class's own :meth:`make` are accepted only
    #: while that ``make`` is the one in use. By default
    #: :func:`_declared_keywords` takes every ``make`` in the MRO, so a subclass
    #: that overrides ``make`` and forwards the rest to its parent keeps the
    #: parent's keywords. A base whose subclasses override ``make`` *without*
    #: forwarding sets this, so that its keywords are refused for them rather than
    #: accepted and dropped -- :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`
    #: does, for ``len`` and ``data`` (:issue:`2286`). Read from the defining
    #: class alone, so it is not inherited, and it leaves :attr:`__keywords__`
    #: and the other construction methods unaffected.
    __own_make_keywords__: 'bool' = False

    #: Whether this instance is being rebuilt by :meth:`from_data` from a parsed
    #: data model, as against constructed from keywords somebody wrote. It governs
    #: only whether the construction keyword check of :meth:`__init__` raises or
    #: warns, and is set for the duration of that call alone; the class-level
    #: :data:`False` is what every other code path sees, including an instance
    #: built without ``__init__``.
    __reconstructing__: 'bool' = False

    #: Caller supplied parsing context; see :mod:`pcapkit.corekit.context`.
    #: :meth:`self.__init__ <Protocol.__init__>` replaces this with a real
    #: :class:`~pcapkit.corekit.context.ContextRegistry`; the class-level
    #: :data:`None` is what an instance built without ``__init__`` (e.g.
    #: ``object.__new__(SomeProtocol)``) sees, so reading it is always safe.
    _exctx: 'Optional[ContextRegistry]' = None

    #: Whether this layer is past :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`, and so was kept as
    #: :class:`~pcapkit.protocols.misc.raw.Raw` by :meth:`_parse_next_layer`
    #: without being parsed. Such a layer carries an ``error`` as one that
    #: failed to parse does, so this is what tells the two apart: what follows
    #: the limit is not to be read on (:issue:`1610`).
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
            :class:`~pcapkit.protocols.misc.null.NoPayload` has no chain and
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
            The split relies on :attr:`self.length <length>` being the length of
            the octets *preceding* the payload, and on the payload running from
            there to the end of the buffer. Both hold for a protocol laid out as
            a header followed by its payload, which is nearly all of them.

            A protocol laid out otherwise has to override this: one whose
            :attr:`~length` counts something else, or one carrying a *trailer*
            after the payload, gets a header that eats the payload and a payload
            of ``b''``. :class:`~pcapkit.protocols.misc.pcapng.PCAPNG` is the
            example -- its :attr:`~pcapkit.protocols.misc.pcapng.PCAPNG.length`
            is the wire's Block Total Length and the captured octets sit ahead of
            the option list and the trailing length field. The payload matters
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
            The ``**kwargs`` here absorbs the keywords that
            :meth:`Protocol.__post_init__
            <pcapkit.protocols.protocol.Protocol.__post_init__>` hands to the
            parse as well as to the construction, so an implementation is not
            expected to declare every keyword it is called with. It is *not* a
            place for a caller to put a keyword no signature declares: building a
            protocol *through its constructor* with such a keyword raises
            :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` from
            :meth:`Protocol.__init__
            <pcapkit.protocols.protocol.Protocol.__init__>` (:issue:`617`).

        Warning:
            **Calling this method directly is not checked**, and still discards an
            undeclared keyword in silence. The check lives in
            :meth:`Protocol.__init__
            <pcapkit.protocols.protocol.Protocol.__init__>`, so it covers
            ``SomeProtocol(...)`` and the :meth:`pack` it leads to, but not
            ``SomeProtocol.make(...)`` on an instance obtained some other way --
            ``object.__new__(cls).make(**kwargs)`` is the idiom, used by this
            package's own tests and by :meth:`HTTP.make
            <pcapkit.protocols.application.http.HTTP.make>` to reach its versioned
            implementation. Covering it would mean interposing on every ``make``
            in the tree rather than on the one place their keywords converge, so
            it is deliberately not done. Construct through the constructor to get
            the check.

        """

    def pack(self, **kwargs: 'Any') -> 'bytes':
        """Pack (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Notes:
            The special keyword argument ``__packet__`` passes the global
            packet data to underlying methods. This is useful when the packet
            data is not available in the current instance.

            The octets are built from ``kwargs`` alone, through :meth:`make`;
            the instance's own parsed or constructed state is not read. A bare
            ``SomeProtocol(...).pack()`` therefore returns the octets of a
            default header, not the instance's: :attr:`data` holds those.

            Nor is that state written. Once the instance has been parsed or
            constructed, the header is made on a shallow copy of it (see
            :meth:`_packing_target`), so :attr:`schema`, :attr:`info` and
            anything :meth:`make` sets along the way, such as
            :attr:`TCP.connection <pcapkit.protocols.transport.tcp.TCP.connection>`,
            still describe that packet. Only the call that
            :meth:`__post_init__` makes to construct the instance keeps the
            header made here, as the one :meth:`unpack` reads back.

        .. versionchanged:: 1.5.0

           Calling it no longer replaces the instance's
           :attr:`__header__ <Protocol.__header__>`, which left :attr:`schema`
           disagreeing with :attr:`info` (:issue:`1769`).

        """
        target = self._packing_target()
        header = target.__header__ = target.make(**kwargs)
        #: bool: If the made header may hold raw items (see :meth:`unpack`).
        target._make_raw = _passes_raw(kwargs) or any(  # pylint: disable=protected-access
            isinstance(header.get(name), bytes) for name in _schema_slots(type(header)))
        packet = kwargs.get('__packet__', {})  # packet data
        return header.pack(packet)

    def unpack(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> '_PT':
        """Unpack (parse) packet data.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Notes:
            The special keyword argument ``__packet__`` passes the global
            packet data to underlying methods. This is useful when the packet
            data is not available in the current instance.

            When :attr:`self.__header__ <Protocol.__header__>` is already set,
            by :meth:`from_schema` or by the :meth:`pack` call that
            :meth:`__post_init__` makes to construct the instance, that schema
            is kept, unless it still holds raw :obj:`bytes` where parsing its
            packed octets yields a schema -- e.g. a raw option given to
            ``make()`` -- which :meth:`read` cannot consume. The header is
            then replaced by the parsed one (:issue:`1312`).

        Raises:
            ProtocolError: If the made header holds raw items and its packed
                octets do not parse, either as a schema or by :meth:`read`.
                The message carries the original error's, which is also
                chained as ``__cause__``.

        """
        packet = kwargs.get('__packet__', {})  # packet data
        if cast('Optional[_ST]', self.__header__) is None:
            self.__header__ = cast('_ST', self.__schema__.unpack(self._file, length, packet))  # type: ignore[call-arg,misc]
        elif self._make_raw and _holds_raw(self.__header__):
            # NOTE: A schema may accept octets that :meth:`read` then rejects,
            # e.g. an option whose length runs past the option area, so the
            # read is covered too (#1394).
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
           the existing registered protocol class from
           :data:`pcapkit.protocols.__proto__` and follow **step 2**; otherwise,
           return the value in upper case alone.

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
            Parsed payload as a :class:`~pcapkit.protocols.protocol.ProtocolBase`
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
            pcapkit.utilities.warnings.RegistryWarning: If ``code`` is already
                registered, naming the displaced entry and its replacement so a
                caller can tell *what* was lost rather than only that something
                was. Fires only when the incumbent differs from the
                replacement; an unresolved
                :class:`~pcapkit.corekit.module.ModuleDescriptor` incumbent
                counts as different from the class it names.

        Note:
            The guard matches :func:`register_protocol
            <pcapkit.foundation.registry.protocols.register_protocol>`'s: it
            fires only when the incumbent differs from the replacement, so
            handing back the entry already stored under ``code`` -- the same
            class object, or a :class:`~pcapkit.corekit.module.ModuleDescriptor`
            equal to the stored one -- is a silent no-op rather than a warning
            about nothing displaced, and the stored entry is kept as it is
            (:issue:`1364`). The comparison runs before ``protocol`` is
            resolved and resolves nothing, so a stored descriptor stays
            deferred, and an incumbent left as an unresolved descriptor still
            reports as different from the class it names.

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
    def from_data(cls, data: '_PT | dict[str, Any]', **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        ``data`` may be the :obj:`dict` that :meth:`Info.to_dict
        <pcapkit.corekit.infoclass.Info.to_dict>` returns, which carries the
        metadata the rebuild reads: ``__next_name__`` and ``__next_type__``,
        which the payload is dispatched on, ``__short_read__``, and, for
        :class:`~pcapkit.protocols.internet.ipv6.IPv6`, the extension header
        chain under ``__exthdr__``. A hand-written :obj:`dict` must carry them
        too, or no payload (nor IPv6 extension header) is rebuilt and no short
        read is cut back, see :meth:`_make_payload`; nothing is guessed from
        its other keys (:issue:`2003`).

        Args:
            data: Protocol data.
            **kwargs: Construction keywords that ``data`` does not carry, such as
                the ``num`` and ``header`` of
                :class:`~pcapkit.protocols.misc.pcap.frame.Frame`, or the
                ``num``, ``sct`` and ``ctx`` of
                :class:`~pcapkit.protocols.misc.pcapng.PCAPNG`. They take
                precedence over the keywords :meth:`_make_data` returns.

        Returns:
            Protocol instance.

        Raises:
            UnsupportedCall: If any of ``kwargs`` matches no parameter of the
                protocol, as for a direct construction.

        """
        if not isinstance(data, Data):
            data = cast('_PT', cls.__data__.from_dict(data))

        # NOTE: The caller typed these, so they are checked strictly here, as a
        # direct construction would check them. The out-of-band keywords
        # ``__init__`` consumes are left out of it.
        _check_construction_keywords(cls, {
            key: val for key, val in kwargs.items()
            if key not in ('_layer', '_protocol', '__context__')
        })

        self = cls.__new__(cls)
        kwargs = {**self._make_data(data), **kwargs}

        # NOTE: The rest came out of ``_make_data``, not out of a caller, so the
        # construction keyword check of ``__init__`` warns here instead of
        # raising: a key of that mapping which disagrees with the signature it is
        # spread into is a defect in this protocol, and the caller of
        # ``from_data`` can do nothing about it. Set for the duration of the call
        # and removed afterwards, so the instance is indistinguishable from one
        # built directly.
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
        #: bool: If a header set before :meth:`unpack` may hold raw items;
        #: :meth:`pack` narrows it down for a made one.
        self._make_raw = True

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
            _protocol: Parse packet until ``_protocol``
                (:attr:`self._exproto <pcapkit.protocols.protocol.Protocol._exproto>`),
                given as a protocol name (:obj:`str`), a protocol class or a
                protocol instance.
                While parsing, the un-prefixed ``protocol`` is accepted as well --
                see the note below.
            packet: Packet context of the enclosing layer, a :obj:`dict` as
                handed over by
                :meth:`self._import_next_layer
                <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
                While parsing, it is republished as ``__packet__`` so that
                :meth:`self.unpack <Protocol.unpack>` -- and through it the
                schema -- can see it; see the note below.
            __context__: Caller supplied parsing context (:attr:`self._exctx <pcapkit.protocols.protocol.Protocol._exctx>`;
                see :mod:`pcapkit.corekit.context`): a
                :class:`~pcapkit.corekit.context.ContextRegistry`, a
                :class:`~pcapkit.corekit.context.ProtocolContext`, a mapping of
                names to :class:`~pcapkit.corekit.context.ProtocolContext`, or an
                iterable of :class:`~pcapkit.corekit.context.ProtocolContext`.
                It is consumed here rather
                than being forwarded to :meth:`self.read <Protocol.read>`, and is
                propagated to nested layers by
                :meth:`self._import_next_layer
                <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            UnsupportedCall: When constructing (``file`` is :obj:`None`), if a
                keyword names no parameter of this protocol's :meth:`make`,
                :meth:`read`, :meth:`pack`, :meth:`unpack`,
                :meth:`__post_init__` or :meth:`__init__`, anywhere in the MRO
                -- except a ``make`` whose class sets
                :attr:`__own_make_keywords__`, which counts only while it is
                the ``make`` of the protocol being constructed -- and is not
                listed in :attr:`__keywords__`. Parsing (``file`` is given) is
                unaffected.

        Note:
            The ``_layer``, ``_protocol`` and ``__context__`` keywords are
            *out-of-band*: they configure the parse rather than describing the
            packet, and every one of them is consumed here, at the one point
            each of a protocol's producers passes through. That is deliberate,
            and the normalisation below relies on it: fixing a spelling here
            fixes it for the engines, for every
            :meth:`_import_next_layer
            <pcapkit.protocols.protocol.Protocol._import_next_layer>`
            implementation, and for any third party protocol that copied their
            shape, rather than one call site at a time.

            ``packet`` is read but not consumed: it stays in the keywords
            forwarded to :meth:`__post_init__`, and while parsing a copy is
            republished beside it as ``__packet__``.

        """
        #logger.debug('%s(file, %s, **%s)', type(self).__name__, length, kwargs)

        # Whether this instantiation parses an existing packet rather than
        # constructing a new one; ``__post_init__`` turns on the same ``file``.
        # ``layer``, ``protocol`` and ``packet`` are out-of-band only while
        # parsing -- on the construction path they are ordinary ``make()``
        # arguments, and consuming them there would silently drop the value
        # being constructed.
        parsing = file is not None

        #: int: File pointer.
        self._seekset = io.SEEK_SET  # type: int
        #: Parse packet until such layer.
        self._exlayer = kwargs.pop('_layer', None)  # type: Optional[str]
        #: Parse packet until such protocol.
        self._exproto = kwargs.pop('_protocol', None)  # type: Optional[str | ProtocolBase | Type[ProtocolBase]]

        # NOTE: The parse limits are documented as ``_layer`` and ``_protocol``,
        # but no producer in the tree spells them that way. The engines build the
        # outermost protocol with ``layer=``/``protocol=``
        # (``pcapkit.foundation.engines.pcap.PCAP.read_frame`` and
        # ``pcapkit.foundation.engines.pcapng.PCAPNG.read_frame``), every
        # ``_import_next_layer`` recurses into the next one the same way, and the
        # un-prefixed pair is the public spelling of
        # ``pcapkit.extract(layer=..., protocol=...)`` and the CLI's ``-L``/``-P``.
        # Left in ``**kwargs`` they would be ignored, so both spellings are
        # accepted (GH-356); the prefixed one wins, so a caller following this
        # docstring is not overridden by a limit its parent happened to forward.
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
        #: bool: Whether to stop parsing the next layer of protocol.
        self._sigterm = self._check_term_threshold()

        # NOTE: The enclosing layer's packet context arrives as ``packet=`` -- the
        # spelling ``_import_next_layer`` uses -- but the schema layer reads it
        # from ``__packet__`` (``self.unpack`` below, and the ``pack``/``unpack``
        # overrides of ``Frame`` and ``PCAPNG``). Republishing it here, for the
        # same reason the limits above are normalised here, is what lets a
        # schema's ``unpack``/``post_process`` see what the outer layer put in it:
        # the ``IPv6`` source address that the HOPOPT MPL option elides from the
        # wire (RFC 7731), and the destination address that the RPL source route
        # header needs to decompress (RFC 6554). See GH-382.
        #
        # A copy rather than the dict itself: ``Schema.unpack`` writes every field
        # it reads into the context it is given, plus its own ``__length__`` and
        # ``__option_padding__`` bookkeeping, and the IPv6 extension header walk
        # hands one dict to each header in turn. Sharing it would leave one
        # header's fields visible to the next, where a ``ConditionalField`` test
        # or a length callback could read a sibling's stale value instead of
        # failing. ``Schema.unpack`` isolates its own per-field contexts the same
        # way.
        if parsing and '__packet__' not in kwargs and isinstance(kwargs.get('packet'), dict):
            kwargs['__packet__'] = dict(kwargs['packet'])

        # NOTE: Construction only. A keyword that names no parameter of this
        # protocol is a mistake rather than a value. Every ``make`` in the tree
        # ends its signature with ``**kwargs``, and none but the dispatching
        # ``HTTP.make`` reads it, so an unknown
        # keyword would reach the schema as nothing at all and the field would
        # keep its default -- ``TCP_BASE`` asking for ``seq=1``, which
        # ``TCP.make`` spells ``seq_no``, would yield ``seq = 0`` with no warning
        # (#617). The schema layer is not that permissive: :meth:`Schema.__update__
        # <pcapkit.protocols.schema.schema.Schema.__update__>` warns
        # :exc:`~pcapkit.utilities.warnings.UnknownFieldWarning` for a field it
        # does not know, and this closes the asymmetry from the other end.
        #
        # Parsing is left alone. There, the keywords are not field values but
        # whatever the engines and the ``_import_next_layer``
        # implementations forward -- ``alias``, ``packet``, and the limits
        # normalised above -- and a protocol has no way to know which of its
        # ancestors' keywords its parent chose to pass on. Nothing is lost that
        # way either: a dropped parse keyword changes how a packet is read, not
        # what the octets say.
        if not parsing:
            _check_construction_keywords(
                type(self), kwargs, strict=not self.__reconstructing__)

        # post-init customisations
        self.__post_init__(file, length, **kwargs)  # type: ignore[arg-type]

        # inject packet payload into the data model
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

        This method is called when a subclass of :class:`ProtocolBase` is defined.
        It is used to set the :attr:`self.__schema__ <pcapkit.protocols.protocol.Protocol.__schema__>`
        and :attr:`self.__data__ <pcapkit.protocols.protocol.Protocol.__data__>`
        attributes of the subclass, and, if ``code`` is given, to register the
        subclass into the next-layer dispatch :term:`registry` (or registries) that
        ``code`` names -- e.g. :attr:`Link.__proto__
        <pcapkit.protocols.link.link.Link.__proto__>`.

        Notes:
            When ``schema`` and/or ``data`` is not specified, the method will first
            try to find the corresponding class in the
            :mod:`~pcapkit.protocols.schema` and :mod:`~pcapkit.protocols.data`
            modules respectively. If the class is not found, the default
            :class:`~pcapkit.protocols.schema.misc.raw.Raw` and
            :class:`~pcapkit.protocols.data.misc.raw.Raw` classes will be used.

        Dispatch registration is **opt-in**, like the ``engine=``/``protocol=``/
        ``fmt=`` keywords of :class:`~pcapkit.foundation.engines.engine.Engine`,
        :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly`,
        :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` and
        :class:`~pcapkit.dumpkit.common.Dumper`. Omitting ``code`` is a
        deliberate way to decline registration, and what every built-in
        protocol class does: the built-in dispatch tables (e.g.
        :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`) are populated by
        literal assignment in each layer module, not by this hook. A subclass that declines can
        still be registered later via the owning class's :meth:`register` classmethod or the
        matching ``register_*`` helper in :mod:`pcapkit.foundation.registry.protocols`.

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
        :exc:`~pcapkit.utilities.exceptions.RegistryError` rather than doing
        nothing or picking an arbitrary registry.

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

        # NOTE: a class defining its own ``__proto__`` ships what its body put
        # there; copy it now, before anything can register into it, so that
        # ``_next_layer_entry`` can restore a shipped descriptor without
        # resolving it (#1504). A class that inherits ``__proto__``
        # inherits this copy with it.
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
            Key-value pairs for protocol construction.

        """
        return data.to_dict()

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
            <pcapkit.protocols.misc.pcap.frame.Frame.pack>` and
            :meth:`PCAPNG.pack <pcapkit.protocols.misc.pcapng.PCAPNG.pack>` do.
            The copy is shallow, so a :meth:`make` that mutates a container
            in place still reaches the instance's.

        """
        # NOTE: ``_info`` is the last thing ``__post_init__`` sets, from
        # ``unpack``; until then the instance holds no packet to keep.
        if '_info' not in vars(self):
            return self
        return copy.copy(self)

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
        prefix = data[pos:pos + size]
        if len(prefix) != size:
            raise ProtocolError(f'{self.alias}: invalid format: {what} length runs past the end of the buffer')
        start = pos + size
        end = start + int.from_bytes(prefix, 'big')
        octets = data[start:end]
        if len(octets) != end - start:
            raise ProtocolError(f'{self.alias}: invalid format: {what} runs past the end of the buffer')
        return octets, end

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

    def _make_uint(self, value: 'Any', *, bits: 'int', name: 'str') -> 'int':
        """Check that ``value`` is an unsigned integer that fits in ``bits`` bits.

        A :obj:`bool` passes only for a one-bit field, so that a flag given
        for a wider field is refused rather than read as ``0`` or ``1``.

        Args:
            value: the value given for the field
            bits: width of the field, in bits
            name: name of the field, for the error message

        Returns:
            ``value`` as a plain :class:`int`.

        Raises:
            ProtocolError: If ``value`` is not an :class:`int`, is a
                :obj:`bool` for a field wider than one bit, is negative, or
                does not fit in ``bits`` bits. The message names
                :attr:`alias`.

        .. versionadded:: 1.6.0

        """
        if (not isinstance(value, int) or (isinstance(value, bool) and bits != 1)
                or not 0 <= value < (1 << bits)):
            raise ProtocolError(f'{self.alias}: invalid {name}: {value!r}')
        return int(value)

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
            StructError: If ``pack`` is :data:`True` and the index could not be
                packed into ``size`` octets.

        Note:
            If ``name`` is a :obj:`str` and ``namespace`` is :data:`None`,
            the namespace is inferred from the calling ``make`` method: it
            is the enumeration class of the default value of the argument
            that ``name`` was passed as, found from the call in the
            caller's source (see ``_make_index_namespace()``).

        """
        if isinstance(name, (enum.Enum, aenum.Enum)):
            index = cast('int', name.value)
        elif isinstance(name, int):
            index = name
        else:  # name is str
            if namespace is None:
                namespace = cls._make_index_namespace(name, inspect.currentframe())
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
                    # Caught by the handler below, so this never escapes: it jumps
                    # to the shared "name is not in namespace" path. A pcapkit
                    # exception here would log at CRITICAL for something the
                    # ``except`` below handles.
                    raise KeyError(name)
            except KeyError as error:
                if default is None:
                    raise ProtocolNotImplemented(f'protocol {name!r} not implemented') from error
                index = default

        if pack:
            return cls._make_pack(index, size=size, signed=signed, lilendian=lilendian)
        return index

    @classmethod
    def _make_index_namespace(cls, name: 'str',
                              frame: 'Optional[FrameType]') -> 'Optional[Type[StdlibEnum] | Type[AenumEnum]]':
        """Infer the enumeration namespace of ``name`` for :meth:`_make_index`.

        The caller of :meth:`_make_index` (``frame.f_back``) is looked up
        among the methods of ``cls``. An argument ``arg`` of that method
        matches if it is accompanied by an ``arg_namespace`` argument that
        is :data:`None`, its current value is a :obj:`str` equal to
        ``name``, and its default
        value is an :class:`~enum.IntEnum` (or ``aenum.IntEnum``)
        member. The candidate namespace of a match is the class of that
        default value.

        Only the argument the call passes as ``name`` is considered: the
        caller's source is parsed (by ``_make_index_calls``) for the
        :meth:`_make_index` call spanning the current line, and its first
        argument names the method argument, so two arguments holding the
        same member name each resolve against their own enumeration. Every
        argument is considered when that call cannot be located (e.g. the
        source is unavailable) or its first argument is not an argument of
        the method (e.g. ``value = arg; self._make_index(value)``).

        Args:
            name: member name given to :meth:`_make_index`
            frame: frame of :meth:`_make_index`

        Returns:
            The candidate namespace if exactly one argument matches. If
            several match, any candidate, provided every candidate has
            ``name`` as a member and maps it to the same value.
            :data:`None` if the caller is not found, nothing matches, or no
            candidate has ``name`` as a member.

        Raises:
            ProtocolNotImplemented: If every argument is considered, several
                arguments match and their candidates disagree on ``name``:
                some lack it, or they map it to different values.

        """
        caller = frame.f_back if frame is not None else None
        if caller is None:
            return None
        try:
            code = caller.f_code
            values = caller.f_locals

            func = None
            for klass in cls.__mro__:
                for attr in vars(klass).values():
                    attr = getattr(attr, '__func__', attr)
                    if getattr(attr, '__code__', None) is code:
                        func = attr
                        break
                if func is not None:
                    break
            if func is None:
                return None

            params = inspect.signature(func).parameters
            lineno = caller.f_lineno
            located = {arg for first, last, arg in _make_index_calls(func) if first <= lineno <= last}
            found = {}  # type: dict[str, Type[StdlibEnum] | Type[AenumEnum]]
            for arg, param in params.items():
                # once the call is located, only its own argument is a candidate
                if len(located) == 1 and located <= params.keys() and arg not in located:
                    continue
                value = values.get(arg)
                if f'{arg}_namespace' not in params or not isinstance(value, str) or value != name:
                    continue
                # an explicit namespace resolves that argument by itself
                if values.get(f'{arg}_namespace') is not None:
                    continue
                if isinstance(param.default, (enum.IntEnum, aenum.IntEnum)):
                    found[arg] = type(param.default)
        finally:
            del caller, frame

        if len(found) == 1:
            return next(iter(found.values()))

        known = {arg: int(space[name]) for arg, space in found.items() if name in space.__members__}
        if not known:
            return None
        if len(known) < len(found) or len(set(known.values())) > 1:
            matches = ', '.join(f'{space.__name__}.{name} = {known[arg]}' if arg in known
                                else f'{space.__name__} has no {name!r}' for arg, space in found.items())
            hint = ' or '.join(f'{arg}_namespace=' for arg in found)
            raise ProtocolNotImplemented(f'{cls.__name__}: ambiguous member name {name!r} given to '
                                         f'{", ".join(found)} ({matches}); pass {hint} explicitly')
        return next(iter(found.values()))

    @classmethod
    def _make_payload(cls, data: 'Data') -> 'ProtocolBase':
        """Create payload from ``data`` for protocol construction.

        This method uses ``__next_type__`` and ``__next_name__`` to
        determine the payload type and name. If either of them is missing or
        :data:`None`, or ``data`` holds nothing under ``__next_name__``, a
        :class:`~pcapkit.protocols.misc.null.NoPayload` instance will be
        returned, exactly as for a protocol with no next layer. Otherwise, the
        payload will be constructed by :meth:`Protocol.from_data
        <pcapkit.protocols.protocol.Protocol.from_data>`.

        :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` carries
        both keys, so ``data`` rebuilt from such a :obj:`dict` dispatches as
        the info did. A hand-written :obj:`dict` must carry them too, as it
        must ``__short_read__`` and, for IPv6, ``__exthdr__``: the payload is
        never guessed from the other keys of ``data`` (:issue:`2003`).

        The payload is built one layer further into the frame than this
        protocol, as :meth:`_parse_next_layer` counts it, since each layer built
        parses its own octets again. So rebuilding a frame stops at
        :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT` where parsing it did, rather than that many
        layers below each layer of it (:issue:`1610`). Nor does the payload's
        parse warn of the limit: this protocol's own parse goes over the same
        octets, so the rebuilt frame warns of it once, as the parsed one did.

        Args:
            data: protocol data

        Returns:
            Payload for protocol construction.

        """
        proto = cast('Optional[Type[Protocol]]', data.get('__next_type__'))
        name = cast('Optional[str]', data.get('__next_name__'))
        if (proto is None or not (isinstance(proto, type) and issubclass(proto, ProtocolBase))
                or name is None or name not in data):
            from pcapkit.protocols.misc.null import \
                NoPayload  # pylint: disable=import-outside-toplevel
            return NoPayload()

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
            Every one of these registries is a :class:`collections.defaultdict`
            held on a *class* attribute, shared by every instance of the class in
            the process. So ``registry[code]`` inserts each code it misses, and
            parsing one packet carrying an unrecognised code grows the registry
            permanently.

            The inserted value is what the default factory would have produced
            anyway, so the entry buys nothing. It costs a spurious "already
            registered" warning from the next genuine ``register`` call for that
            code, and makes "is this code registered?" depend on what has been
            parsed. The fallback is therefore read from the default factory
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
                <pcapkit.protocols.protocol.Protocol.__proto__>`. Passed in
                rather than read from the class, so that a caller reaching the
                registry through an instance keeps doing so.
            proto: next layer protocol index

        Returns:
            The class registered for ``proto``, or the fallback ``registry``
            declares -- normally :class:`~pcapkit.protocols.misc.raw.Raw` -- when
            ``proto`` is not registered.

        Important:
            The lookup itself is :meth:`self._lookup_registry
            <pcapkit.protocols.protocol.Protocol._lookup_registry>`, so a miss
            does not grow the shared registry. What this adds is the
            next-layer-specific resolution step: the entry found --
            registered, or the fallback -- may be a
            :class:`~pcapkit.corekit.module.ModuleDescriptor` rather than a
            class, and it is resolved to the class it names.

            Nothing is written back, on a hit or a miss. A miss has no key to
            write under, and recording one would be exactly the insertion
            :meth:`self._lookup_registry
            <pcapkit.protocols.protocol.Protocol._lookup_registry>` exists
            to avoid. A hit memoised under ``proto`` would retain a class that
            :func:`importlib.reload` then makes stale, and would make parsing
            mutate a registry shared by the whole process (:issue:`1559`). The
            same holds for a memo in ``registry``'s default factory or in a cache
            beside the registry (:issue:`421`, :issue:`425`, :issue:`555`).

            So every lookup resolves its descriptor again, and what keeps that
            affordable is :attr:`ModuleDescriptor.klass
            <pcapkit.corekit.module.ModuleDescriptor.klass>` reading
            :data:`sys.modules` instead of re-entering
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

        if min(length, len(file_)) == 0:
            from pcapkit.protocols.misc.null import NoPayload as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.misc.raw import Raw as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        else:
            protocol = self._lookup_next_layer(self.__proto__, proto)

        return self._parse_next_layer(protocol, file_, length, alias=proto, packet=packet,
                                      layer=self._exlayer, protocol=self._exproto,
                                      __context__=self._exctx)

    @staticmethod
    def _parse_next_layer(klass: 'Type[ProtocolBase]', file_: 'bytes', length: 'int',
                          **kwargs: 'Any') -> 'ProtocolBase':
        r"""Parse the next layer, or keep it as raw octets if its header was not captured.

        Arguments:
            klass: next layer protocol class
            file\_: payload of the current layer
            length: valid (*non-padding*) length
            **kwargs: keyword arguments for the next layer's constructor

        Returns:
            Instance of ``klass``, or of :class:`~pcapkit.protocols.misc.raw.Raw`
            when fewer octets were captured than its header needs, or when it is
            past :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`.

        Note:
            :meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>`
            zero-fills a field the stream ends inside, so a header parsed from
            too few octets is filled with values that were never on the wire, and
            :meth:`from_data <Protocol.from_data>` rebuilds them (:issue:`1170`).
            Such a payload is kept as :class:`~pcapkit.protocols.misc.raw.Raw`
            instead, as an unparseable one is.

            The captured octets are the first ``length`` of ``file_``, or all of
            it when it holds fewer, as a truncated capture does. They are short
            of the header when there are fewer than the next layer's
            :meth:`__length_hint__
            <pcapkit.protocols.protocol.Protocol.__length_hint__>`, unless the
            header it parsed, :attr:`length
            <pcapkit.protocols.protocol.Protocol.length>` octets long, fits
            in them anyway: for a variable-length header such as
            :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` the hint is the longest
            form rather than the shortest. A next layer that reports no hint is
            kept as parsed.

            The warnings of a parse that may be replaced are held until it is
            known whether it is. They are dropped when it is, since they describe
            a header the result does not have -- ``packet length < 0`` twice for
            an Ethernet frame of 10 octets (:issue:`1580`) -- and reported as the
            parse ends when it is kept, still inside the guard that catches them
            under an ``error`` filter. A layer kept with its header cut short
            still warns. The held warnings of a parse that raises are dropped
            too when :func:`~pcapkit.corekit.decorators.beholder`, which wraps
            :meth:`_import_next_layer`, replaces the layer, since the
            replacement's ``error`` reports the failure (:issue:`2308`); outside
            ``beholder``, they are reported as the error leaves. Under
            ``beholder``, a layer is held however much was captured, since one
            that raises is replaced at any length (:issue:`2516`), so a kept
            layer's warnings follow those of the layers it carries. Outside
            ``beholder``, a layer captured at least as long as its hint cannot
            be replaced, and is parsed holding nothing, even inside one that
            holds.

            A layer past :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT` in its frame is not parsed:
            it and the rest of the frame are kept as
            :class:`~pcapkit.protocols.misc.raw.Raw`, marked
            :attr:`_past_layer_limit`, with one
            :exc:`~pcapkit.utilities.warnings.ProtocolWarning` (:issue:`1610`).

        Warns:
            ProtocolWarning: If the next layer is past :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`.

        """
        depth = frame_depth.get() + 1
        limit = config.FRAME_LAYER_LIMIT
        if limit != -1 and depth > limit:
            from pcapkit.protocols.misc.null import NoPayload  # isort: skip # pylint: disable=import-outside-toplevel
            from pcapkit.protocols.misc.raw import Raw  # isort: skip # pylint: disable=import-outside-toplevel

            # NOTE: Nothing is lost if the next layer is raw already, or empty.
            if klass is not Raw and klass is not NoPayload:
                message = (f'the frame reached the limit of {limit} layers; the rest of it, '
                           f'from {klass.__name__} on, is left undissected')
                # NOTE: Inside a payload being rebuilt, the layer it is rebuilt
                # for warns of the same octets once its own parse gets here.
                if not rebuilding.get():
                    warn(message, ProtocolWarning, stacklevel=stacklevel())
                raw = Raw(file_, length, **{**kwargs, 'error': message})
                raw._past_layer_limit = True  # pylint: disable=protected-access
                return raw

        captured = min(length, len(file_))
        token = frame_depth.set(depth)
        try:
            # NOTE: Under ``beholder`` a layer that raises is replaced at any length,
            # so its warnings are held however much was captured (#2516).
            with hold_warnings(beholding.get() or _short_of_hint(klass, captured)) as held:
                try:
                    next_ = klass(file_, length, **kwargs)  # type: ignore[abstract]
                except Exception:
                    # NOTE: Under ``beholder`` the layer that raised is replaced,
                    # so its warnings go with it; outside it, the error reaches
                    # the caller and they are reported as it leaves (#2308).
                    held.discard = beholding.get()
                    raise

                length_hint = getattr(next_, '__length_hint__', None)
                hint = None if length_hint is None else length_hint()
                held.discard = hint is not None and captured < hint and captured < next_.length
        finally:
            frame_depth.reset(token)
        if held.discard:
            from pcapkit.protocols.misc.raw import Raw  # isort: skip # pylint: disable=import-outside-toplevel
            next_ = Raw(file_, length, **kwargs)
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
    """User-facing abstract base class for third-party protocols.

    Inherit it directly only to create a new protocol stack; a new protocol in
    an existing layer subclasses that layer's base class instead; see
    :doc:`/ext`. The built-in protocol families do not derive from this class
    but from :class:`ProtocolBase`, whose metaclass is :class:`ProtocolMeta`.

    .. versionchanged:: 1.3.0

       The built-in protocol families derive from :class:`ProtocolBase`, so a
       built-in protocol is not an instance of this class, where every one
       was; and a subclass is registered in :data:`pcapkit.protocols.__proto__`
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

        This method is called when a subclass of :class:`Protocol` is defined.
        It is used to set the :attr:`self.__schema__ <pcapkit.protocols.protocol.Protocol.__schema__>`
        and :attr:`self.__data__ <pcapkit.protocols.protocol.Protocol.__data__>`
        attributes of the subclass.

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
