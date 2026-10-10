# -*- coding: utf-8 -*-
"""Common Utilities
======================

.. module:: pcapkit.dumpkit.common

:mod:`pcapkit.dumpkit.common` is the collection of common utility
functions for :mod:`pcapkit.dumpkit` implementation, which is
generally the customised hooks for :class:`dictdumper.Dumper`
classes.

"""
import collections
import datetime
import decimal
import enum
import inspect
import ipaddress
import json
import re
import string
import types
import xml.sax.saxutils
from typing import TYPE_CHECKING

import aenum
import dictdumper.dumper
import dictdumper.json
import dictdumper.plist
import dictdumper.tree

from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
from pcapkit.corekit.sentinels import NoValueType, NullType
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import UnsupportedCall
from pcapkit.utilities.logging import get_logger

__all__ = ['make_dumper']


if TYPE_CHECKING:
    from typing import Any, DefaultDict, Iterator, Optional, TextIO, Type

    from dictdumper.dumper import Dumper as ABCDumper
    from typing_extensions import Literal


#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)

#: re.Pattern: A character XML 1.0 does not allow anywhere in a document, not
#: even as a character reference: every C0 control other than tab, LF and CR,
#: the surrogates, and ``U+FFFE``/``U+FFFF`` (XML 1.0, production ``[2] Char``).
_XML_ILLEGAL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]')

#: frozenset[str]: Characters :meth:`dictdumper.json.JSON._append_string`
#: writes as themselves or through its escape table rather than as a
#: ``\uXXXX`` escape.
_JSON_PRINTABLE = frozenset(string.printable)


class DumperBase(dictdumper.dumper.Dumper):
    """Base :class:`~dictdumper.dumper.Dumper` object.

    Note:
        This class is for internal use only. For customisation, please use
        :class:`Dumper` instead.

    """


class Dumper(DumperBase):
    """Base :class:`~dictdumper.dumper.Dumper` object.

    This class is a customised :class:`~dictdumper.dumper.Dumper` for the
    :mod:`pcapkit.dumpkit` implementation, which is generally customised
    for opt-in registration to the
    :class:`~pcapkit.foundation.extraction.Extractor` and
    :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` output
    dumper registries.

    Example:

        Registration is opt-in. Pass keyword argument ``fmt`` at class
        definition to register the dumper under that output format:

        .. code-block:: python

           class MyDumper(Dumper, fmt='my_format', ext='.mine'):
               ...

        Omit it and the subclass is *not* registered:

        .. code-block:: python

           class MyMixin(Dumper):  # not registered
               ...

        Such a class can still be registered later, on demand. Note this hook
        writes *both* output registries, so the equivalent manual call is the
        module-level one that does the same, not either class' own method:

        .. code-block:: python

           from pcapkit.foundation.registry.foundation import register_dumper

           register_dumper('my_mixin', MyMixin, '.mine')

    """

    def __init_subclass__(cls, /, fmt: 'Optional[str]' = None,
                          ext: 'Optional[str]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialise subclass.

        This method is used to register the subclass to the
        :class:`~pcapkit.foundation.extraction.Extractor` and
        :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow`
        output dumper registries.

        Args:
            fmt: Output format to register the subclass under, lowercased.
                :data:`None` (the default) skips registration entirely.
            ext: Output file extension; :data:`None` infers it from ``fmt``.
                Only meaningful alongside ``fmt``.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            UnsupportedCall: If ``ext`` is given without ``fmt``, or if any
                unrecognised class keyword is given.

        Registration is **opt-in**: the subclass is registered if and only if
        ``fmt`` is given. This is what lets a subclass decline registration
        rather than having to inherit :class:`DumperBase` to avoid it, and it
        matches :meth:`EnumSchema.__init_subclass__
        <pcapkit.protocols.schema.schema.EnumSchema.__init_subclass__>`, which
        guards on its own ``code`` keyword the same way.

        Note:
            Inferring ``fmt`` from the subclass'
            :attr:`~dictdumper.dumper.Dumper.kind` property would need an
            *instance*, hence a :func:`tempfile.NamedTemporaryFile` created while
            the ``class`` statement is still executing. Guarding on ``fmt``
            avoids that: a class definition does not touch the filesystem.

        See Also:
            - :func:`pcapkit.foundation.registry.foundation.register_dumper`
            - :func:`pcapkit.foundation.registry.foundation.register_extractor_dumper`
            - :func:`pcapkit.foundation.registry.foundation.register_traceflow_dumper`
            - :meth:`pcapkit.foundation.extraction.Extractor.register_dumper`
            - :meth:`pcapkit.foundation.traceflow.traceflow.TraceFlow.register_dumper`

        """
        # NOTE: as in the four sibling hooks, an unrecognised class keyword would
        # otherwise land in ``**kwargs`` and be dropped by the bare
        # ``super().__init_subclass__()`` below, silently skipping registration.
        if args or kwargs:
            unexpected = ', '.join([*map(repr, args), *sorted(kwargs)])
            raise UnsupportedCall(f'{cls.__name__}: unexpected class keyword(s): {unexpected}')

        # NOTE: ``ext`` alone cannot register anything -- there is no format to
        # register it against -- so it would silently do nothing. Say so instead.
        if fmt is None:
            if ext is not None:
                raise UnsupportedCall(f'{cls.__name__}: ext={ext!r} given without fmt')
            return super().__init_subclass__()

        fmt = fmt.lower()
        if ext is None:
            ext = f'.{fmt}'

        from pcapkit.foundation.extraction import \
            Extractor  # pylint: disable=import-outside-toplevel

        Extractor.register_dumper(fmt, cls, ext)

        from pcapkit.foundation.traceflow.traceflow import \
            TraceFlow  # pylint: disable=import-outside-toplevel

        TraceFlow.register_dumper(fmt, cls, ext)

        return super().__init_subclass__()


def render_enum(o: 'enum.Enum | aenum.Enum') -> 'str':
    """Render an enumeration member as ``Type::name [value]``.

    This is the spelling every dumped enumeration carries in the ``json``,
    ``tree``, ``text``, ``txt``, ``plist`` and ``xml`` output of both
    :class:`~pcapkit.foundation.extraction.Extractor` and
    :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow`, so it lives in
    one function rather than being spelled out at each of the three places
    :func:`make_dumper`'s hook needs it.

    Args:
        o: Enumeration member to render.

    Returns:
        The member's ``Type::name [value]`` rendering.

    Note:
        A :class:`~enum.Flag` value composed **entirely of undeclared bits** has
        no name at all -- :attr:`~enum.Enum.name` is :data:`None`, not a string --
        so interpolating it unguarded would put the literal four characters
        ``None`` into the name half and render
        :class:`~pcapkit.const.tcp.flags.Flags` ``(0)`` as ``'Flags::None [0]'``
        (GitHub issue :issue:`648`).

        Two things make that worth a guard rather than a shrug. ``'None'`` is a
        plausible member name, so a consumer splitting the rendering on ``::``
        cannot tell it from a member genuinely so named -- and ``NONE`` *is* a
        declared name elsewhere in the library. And the defect is not confined to
        zero: ``Flags(1)``, ``Flags(8)`` and ``Flags(65536)`` are every bit as
        nameless, so a guard written against ``value == 0`` would fix one case
        and leave the rest.

        The fallback is the value's own decimal spelling, which is what the
        enumeration libraries themselves already use for an undeclared residue:
        ``Flags(2057).name`` is ``'ACK|9'``, naming the declared bit and giving
        the leftovers as one number. A wholly-undeclared value is that same
        rendering with no declared bit to precede it, so ``Flags(9)`` becomes
        ``'Flags::9 [9]'`` and ``Flags(0)`` becomes ``'Flags::0 [0]'``. It also
        cannot be mistaken for a member name, since a Python identifier may not
        begin with a digit.

        This is *not* an :mod:`aenum` quirk. A stdlib :class:`enum.IntFlag` built
        from the same members answers ``name is None`` identically on CPython
        3.14.7, so the guard belongs here rather than in a choice of enumeration
        library.

    """
    name = o.name
    if name is None:
        name = str(o.value)
    return f'{type(o).__name__}::{name} [{o.value}]'


def _iter_slots(value: 'Any') -> 'Iterator[str]':
    """Yield the names of every slot ``value`` has an assigned value for.

    Args:
        value: Object to inspect.

    Yields:
        Each slot name declared anywhere in ``type(value).__mro__``, base classes
        first and each name once, skipping ``__dict__``, ``__weakref__`` and
        any slot that is unset on ``value``.

    Note:
        ``__slots__`` on a class names only the slots *that* class adds, and
        reading it from an instance finds the nearest class that declares one,
        so a subclass declaring ``__slots__ = ()`` hides all of its bases'
        slots. :class:`ipaddress.IPv6Network` is such a class.

    """
    seen = set()  # type: set[str]
    for klass in reversed(type(value).__mro__):
        names = klass.__dict__.get('__slots__', ())
        if isinstance(names, str):
            names = (names,)
        for name in names:
            if name in seen or name in ('__dict__', '__weakref__'):
                continue
            seen.add(name)
            try:
                getattr(value, name)
            except AttributeError:
                continue
            yield name


#: Most objects :meth:`DictDumper._append_fallback` expands for one top-level
#: object, counting an object once per time it is met. No fallback object in the
#: ``foundation``, ``dumpkit`` or ``interface`` test legs expands into more than 7.
FALLBACK_LIMIT = 10_000


def _object_name(value: 'Any') -> 'str':
    """Name a class, module or routine for dumping, in place of its attributes.

    Args:
        value: Object to name.

    Returns:
        The module-qualified name of ``value``, falling back to :func:`str`
        where it carries none.

    """
    qualname = getattr(value, '__qualname__', None) or getattr(value, '__name__', None)
    if not isinstance(qualname, str):
        return str(value)
    module = getattr(value, '__module__', None)
    if isinstance(module, str) and module != 'builtins' and not isinstance(value, types.ModuleType):
        return f'{module}.{qualname}'
    return qualname


def make_dumper(output: 'Type[ABCDumper]') -> 'Type[ABCDumper]':
    """Create a customised :class:`~dictdumper.dumper.Dumper` object.

    Args:
        output: Output class to customise.

    Returns:
        Customised :class:`~dictdumper.dumper.Dumper` object.

    """
    # NOTE: :class:`~dictdumper.plist.PLIST` -- which is also what
    # :attr:`Extractor.__output__ <pcapkit.foundation.extraction.Extractor.__output__>`
    # maps the ``'xml'`` format to, so the two are the same writer under two
    # names here -- interpolates every ``<string>``/``<key>`` value into its
    # XML-shaped markup with no entity escaping at all: neither ``&``, ``<``
    # nor ``>`` is escaped anywhere in :mod:`dictdumper`. Filed upstream as
    # JarryShaw/DictDumper#125 and tracked here as GitHub issue #772. ``json``,
    # ``tree`` and ``text`` have no such defect and all three characters are
    # legal in their output, so escaping is conditioned on the output class
    # rather than done unconditionally in :func:`render_enum`, which would
    # double-escape those three. :class:`~dictdumper.xml.XML` itself defines
    # no ``_append_string`` of its own -- its own module docstring says not to
    # use it directly -- so :class:`~dictdumper.plist.PLIST` is the only
    # concrete writer this applies to.
    escape_strings = issubclass(output, dictdumper.plist.PLIST)
    # NOTE: :class:`~dictdumper.json.JSON` escapes every string *value* it
    # writes, but interpolates a mapping key into ``'"{item}": '`` raw: a ``"``
    # in a key closes the JSON string early, and a ``\`` escapes the character
    # after it (GitHub issue #1152). The defect is :mod:`dictdumper`'s, so it is
    # worked around here.
    escape_json_keys = issubclass(output, dictdumper.json.JSON)
    escape_keys = escape_strings or escape_json_keys
    # NOTE: :meth:`~dictdumper.plist.PLIST._append_dict` and
    # :meth:`~dictdumper.plist.PLIST._append_array` skip every :data:`None`
    # value and item outright, so a ``plist`` report lacks keys the ``json``
    # report has (GitHub issue #1257). The defect is :mod:`dictdumper`'s, so it
    # is worked around here.
    keep_none = issubclass(output, dictdumper.plist.PLIST)
    # NOTE: :meth:`~dictdumper.plist.PLIST._append_date` writes every date with
    # six fractional digits, which the property list ``<date>`` grammar does not
    # admit, so :func:`plistlib.load` rejects every report (GitHub issue #1448).
    # The defect is :mod:`dictdumper`'s, so it is worked around here.
    plist_dates = issubclass(output, dictdumper.plist.PLIST)
    # NOTE: :meth:`~dictdumper.tree.Tree._append_number` hands every number to
    # :func:`math.isnan`, which raises :exc:`TypeError` for a :class:`complex`
    # one, although :class:`~dictdumper.tree.Tree` routes :class:`complex` there
    # (GitHub issue #1266). The defect is :mod:`dictdumper`'s, so it is worked
    # around here.
    tree_numbers = issubclass(output, dictdumper.tree.Tree)

    def escape_key(key: 'Any') -> 'Any':
        """Escape a mapping key on its way to the writer.

        Args:
            key: Mapping key, as the writer would interpolate it.

        Returns:
            The key unchanged where ``output`` needs no escaping, otherwise the
            escaped text of the writer's own rendering of it.

        Note:
            :meth:`~dictdumper.plist.PLIST._append_dict` writes a key straight
            into ``'<key>{item}</key>'``, and
            :meth:`~dictdumper.json.JSON._append_object` into ``'"{item}": '``;
            both call :meth:`~dictdumper.dumper.Dumper._encode_value` on the
            *value* two lines later, never on the key -- so
            :meth:`DictDumper.object_hook` is handed every value the writer will
            interpolate but no key at all, and cannot escape one on the way out
            the way it does a value. Each branch below that builds a mapping
            therefore escapes its own keys through here.

            A non-:class:`str` key is rendered with :func:`format`, which is the
            very conversion ``'{item}'.format(item=key)`` already applies to it,
            so the key text is unchanged apart from the escaping.
            Rendering such a key rather than passing it over is deliberate:
            :file:`examples/captures/test.pcapng` keys the TLS key log entries
            of its decryption secrets block by a raw :class:`bytes` client
            random (:meth:`TLSKeyLog.post_process
            <pcapkit.protocols.schema.misc.pcapng.TLSKeyLog.post_process>`), and
            the ``bytes`` repr of that one carries ``&``, ``<``, ``>``, ``"``
            *and* ``\\``. Unescaped, that makes the fixture's ``plist`` report
            unparseable at the key's ``&``, and its ``json`` report at the
            key's ``"``.

            For ``json`` the key is escaped by :func:`json.dumps` with the
            surrounding quotes stripped, since the writer supplies its own. Like
            :meth:`~dictdumper.json.JSON._append_string`, that spells every
            non-ASCII character as a ``\\uXXXX`` escape.

        """
        if escape_strings:
            return xml.sax.saxutils.escape(format(key, ''))
        if escape_json_keys:
            return json.dumps(format(key, ''))[1:-1]
        return key

    def fields(info: 'Info | MultiDict[Any, Any]') -> 'dict[Any, Any]':
        """Return the fields of ``info`` as the :class:`dict` the writer is handed.

        Args:
            info: The fields, as an :class:`~pcapkit.corekit.infoclass.Info` or
                as the :class:`~pcapkit.corekit.multidict.OrderedMultiDict` its
                :meth:`~pcapkit.corekit.infoclass.Info.to_dict` returns.

        Returns:
            One entry per field, in order, with its key escaped as
            :func:`escape_key` does. A field held once maps to its value; a field
            held more than once, such as a repeated IPv6 extension header, maps
            to the :class:`list` of all its values, in order (GitHub issue
            :issue:`1484`). The values are left as they are, so each comes back
            through :meth:`DictDumper.object_hook` when written.

        """
        pairs = list(info.items(multi=True))
        counts = collections.Counter(key for key, _ in pairs)
        result = {}  # type: dict[Any, Any]
        for key, val in pairs:
            if counts[key] > 1:
                result.setdefault(escape_key(key), []).append(val)
            else:
                # NOTE: read by indexing, so that a model overriding it is
                # honoured -- the traceflow and reassembly models resolve a
                # deferred ``packet`` there.
                result[escape_key(key)] = info[key]
        return result

    #: Whether the writer is handed the fields of an
    #: :class:`~pcapkit.corekit.infoclass.Info` rather than the object itself:
    #: every writer but the ones :mod:`pcapkit.dumpkit` defines for internal
    #: use, i.e. :class:`~pcapkit.dumpkit.pcap.PCAPIO`, which takes the frame,
    #: and :class:`~pcapkit.dumpkit.null.NotImplementedIO`.
    takes_fields = not issubclass(output, DumperBase) or issubclass(output, Dumper)

    class DictDumper(output):
        """Customised :class:`~dictdumper.dumper.Dumper` object."""

        if takes_fields:
            def __call__(self, value: 'Any', name: 'Optional[str]' = None) -> 'Any':
                """Dump a new block.

                Args:
                    self: Dumper instance.
                    value: Content to be dumped.
                    name: Name of the block.

                Returns:
                    The dumper itself.

                Notes:
                    An :class:`~pcapkit.corekit.infoclass.Info`, or the
                    :class:`~pcapkit.corekit.multidict.MultiDict` its
                    :meth:`~pcapkit.corekit.infoclass.Info.to_dict` returns, is
                    written as the :class:`dict` :func:`fields` makes of it, so
                    that a repeated field keeps every value. The writer walks
                    the block it is handed without calling
                    :meth:`object_hook` on it, only on what it holds.

                """
                if isinstance(value, (Info, MultiDict)):
                    value = fields(value)
                return super().__call__(value, name)

        #: Objects :meth:`_append_fallback` is expanding, by :func:`id` -- the
        #: one being written and every one enclosing it.
        _fallback_path = None  # type: Optional[set[int]]
        #: Objects expanded so far for the current top-level fallback object.
        _fallback_count = 0

        def object_hook(self, o: 'Any') -> 'Any':
            """Convert content for function call.

            Args:
                self: Dumper instance.
                o: object to convert

            Returns:
                Converted object, escaped for XML-shaped output where needed.

            Notes:
                :meth:`~dictdumper.dumper.Dumper._encode_value` -- and so this
                method -- is called once per node the dumper writes, however
                deeply nested, so escaping the :class:`str` result here on the
                way out reaches every string the writer will ever interpolate
                raw, not merely the ones built directly in this method. The
                one exception is a mapping *key*:
                :meth:`~dictdumper.dumper.Dumper._append_dict` writes those
                straight from the mapping without ever calling this method on
                them, so both branches that hand the writer a mapping -- a
                :class:`~pcapkit.corekit.multidict.MultiDict` and a plain
                :class:`dict` -- escape their own keys through
                :func:`escape_key` instead. An
                :class:`~pcapkit.corekit.multidict.OrderedMultiDict` becomes a
                :class:`list` of single-key :class:`dict` objects, each of
                which comes back through the :class:`dict` branch, and so
                does an :class:`~pcapkit.corekit.infoclass.OrderedMultiInfo`,
                the option lists an :class:`~pcapkit.corekit.infoclass.Info`
                holds. An :class:`~pcapkit.corekit.infoclass.Info` itself
                becomes the :class:`dict` of its fields that :func:`fields`
                returns, holding every value of a repeated field.

            """
            if isinstance(o, decimal.Decimal):
                result = str(o)  # type: Any
            elif isinstance(o, datetime.timedelta):
                result = o.total_seconds()
            elif isinstance(o, Info) and not isinstance(o, MultiDict):
                # NOTE: a MultiInfo or OrderedMultiInfo, though an Info, is
                # an option list, and is written by the branches below.
                result = fields(o)
            elif isinstance(o, Schema):
                result = o.to_dict()
            elif isinstance(o, (ipaddress.IPv4Address, ipaddress.IPv6Address,
                                ipaddress.IPv4Network, ipaddress.IPv6Network)):
                result = str(o)
            elif isinstance(o, datetime.timezone):
                result = o.utcoffset(None).total_seconds()
            elif isinstance(o, NullType):
                result = '<NULL>'
            elif isinstance(o, NoValueType):
                result = '<NO_VALUE>'
            elif isinstance(o, OrderedMultiDict):
                # NOTE: one single-key mapping per entry, in insertion order --
                # i.e. wire order for the option lists -- since a mapping keyed
                # by name could only gather the repeats of a key under its first
                # occurrence (GitHub issue #1263). The keys are escaped when the
                # writer hands each mapping back to this hook, through the
                # :class:`dict` branch below.
                result = [
                    {render_enum(key) if isinstance(key, (enum.Enum, aenum.Enum)) else key: val}
                    for key, val in o.items(multi=True)
                ]
            elif isinstance(o, MultiDict):
                # NOTE: a :class:`MultiDict` keeps no order across keys, only
                # among the values of each, so grouping by key loses nothing.
                temp = collections.defaultdict(list)  # type: DefaultDict[str, list[Any]]
                for key, val in o.items(multi=True):
                    if isinstance(key, (enum.Enum, aenum.Enum)):
                        key = render_enum(key)
                    temp[escape_key(key)].append(val)
                result = temp
            elif isinstance(o, dict):
                # NOTE: rebuilt only where the keys need escaping, so every other
                # output is still handed the caller's own mapping rather than a
                # copy of it.
                if escape_keys:
                    result = {escape_key(key): val for key, val in o.items()}
                else:
                    result = o
            elif isinstance(o, (enum.Enum, aenum.Enum)):
                addon = {key: val for key, val in o.__dict__.items() if not key.startswith('_')}
                if addon:
                    result = {
                        'enum': render_enum(o),
                        **addon,
                    }
                else:
                    result = render_enum(o)
            else:
                result = super(type(self), self).object_hook(o)

            if escape_strings and isinstance(result, str):
                # NOTE: XML 1.0 has no spelling at all for some characters, not
                # even a character reference, so a string holding one is written
                # as ``<data>``, the way :class:`bytes` already is (GitHub issue
                # #1262).
                if _XML_ILLEGAL.search(result) is not None:
                    return result.encode('utf-8', 'surrogatepass')
                return xml.sax.saxutils.escape(result)
            return result

        if keep_none:
            def _append_dict(self, value: 'dict[Any, Any]', file: 'TextIO') -> 'None':
                """Call this function to write dict contents.

                Args:
                    self: Dumper instance.
                    value: Content to be dumped.
                    file: Output file.

                Notes:
                    Each :data:`None` value is first converted through
                    :meth:`~dictdumper.plist.PLIST._encode_value`, whose own
                    rendering of it is ``{'type': 'NoneType', 'value': 'None'}``,
                    so that the writer no longer skips it.

                """
                value = {key: self._encode_value(val) if val is None else val for key, val in value.items()}
                super()._append_dict(value, file)

            def _append_array(self, value: 'list[Any]', file: 'TextIO') -> 'None':
                """Call this function to write array contents.

                Args:
                    self: Dumper instance.
                    value: Content to be dumped.
                    file: Output file.

                Notes:
                    As :meth:`_append_dict`, for each :data:`None` item.

                """
                value = [self._encode_value(item) if item is None else item for item in value]
                super()._append_array(value, file)

        if plist_dates:
            def _append_date(self, value: 'datetime.date', file: 'TextIO') -> 'None':
                """Call this function to write date contents.

                Args:
                    self: Dumper instance.
                    value: Content to be dumped.
                    file: Output file.

                Notes:
                    The date is written in UTC to whole seconds, as
                    :func:`plistlib.dump` writes one: an aware value is
                    converted to UTC first, a naive one is taken as UTC already,
                    and the sub-second part of the :class:`~datetime.datetime`
                    is truncated. That value is already rounded to the
                    microsecond where it is parsed, so within half a microsecond
                    of a second boundary the date is one second past the floor
                    of a finer ``*_epoch``. The exact value is not
                    lost: every timestamp pcapkit reports sits next to a field
                    that carries it exactly -- a :class:`~decimal.Decimal`
                    ``*_epoch`` for frames and PCAP-NG blocks and options, e.g.
                    ``time_epoch``, and the raw ``ntp_timestamp`` or
                    ``pmip_timestamp`` for the two MH options.

                """
                if isinstance(value, datetime.datetime) and value.tzinfo is not None:
                    value = value.astimezone(datetime.timezone.utc)
                # NOTE: not :meth:`~datetime.date.strftime`, whose ``%Y`` does not
                # zero-pad a year below 1000 on every platform.
                hour, minute, second = (getattr(value, name, 0)
                                        for name in ('hour', 'minute', 'second'))
                tabs = '\t' * self._tctr
                file.write(f'{tabs}<date>{value.year:04d}-{value.month:02d}-{value.day:02d}'
                           f'T{hour:02d}:{minute:02d}:{second:02d}Z</date>\n')

        if escape_json_keys:
            def _append_string(self, value: 'str', file: 'TextIO') -> 'None':
                """Call this function to write string contents.

                Args:
                    self: Dumper instance.
                    value: Content to be dumped.
                    file: Output file.

                Notes:
                    :meth:`dictdumper.json.JSON._append_string` writes every
                    other character as ``'\\u{0:04x}'.format(ord(char))``, which
                    for a code point above ``U+FFFF`` yields five or six hex
                    digits that a reader takes as one escape and literal text
                    (GitHub issue #1261). This writes such a character as a
                    UTF-16 surrogate pair instead, as :func:`json.dumps` does, and
                    every other character exactly as the upstream writer does.

                """
                text = []  # type: list[str]
                for char in value:
                    if char in _JSON_PRINTABLE:
                        text.append(dictdumper.json.ESCAPE_DCT.get(char, char))
                    else:
                        text.append(json.dumps(char)[1:-1] if ord(char) > 0xFFFF else f'\\u{ord(char):04x}')
                file.write('"' + ''.join(text) + '"')

        if tree_numbers:
            def _append_number(self, value: 'int | float | complex', file: 'TextIO') -> 'None':
                """Call this function to write number contents.

                Args:
                    self: Dumper instance.
                    value: Content to be dumped.
                    file: Output file.

                Notes:
                    A :class:`complex` value is written as ``-> (1+2j)``, with
                    ``NaN`` and ``Infinity`` spelt in either part as
                    :meth:`dictdumper.tree.Tree._append_number` spells them for a
                    :class:`float`; every other number is written by the
                    upstream writer.

                """
                if not isinstance(value, complex):
                    return super()._append_number(value, file)
                text = str(value).replace('nan', 'NaN').replace('inf', 'Infinity')
                file.write(f'-> {text}')
                return None

        def default(self, o: 'Any') -> 'Literal["fallback"]':  # pylint: disable=unused-argument
            """Check content type for function call.

            Args:
                self: Dumper instance.
                o: Object to check.

            Returns:
                Fallback string.

            Notes:
                This function is a fallback for :meth:`dictdumper.dumper.Dumper.default`.
                It will be called when :meth:`dictdumper.dumper.Dumper.default` fails
                to find a suitable function for dumping and it should pair with
                ``_append_fallback`` for use.

            """
            return 'fallback'

        def _append_fallback(self, value: 'Any', file: 'TextIO') -> 'None':
            """Fallback function for dumping.

            Args:
                self: Dumper instance.
                value: Value to dump.
                file: File object to write.

            Notes:
                This function is a fallback for :meth:`dictdumper.dumper.Dumper.default`.
                It will be called when :meth:`dictdumper.dumper.Dumper.default` fails
                to find a suitable function for dumping and it should pair with
                ``default`` for use.

                A class, module or routine is written as its name rather than
                expanded, since its attributes reach the whole type graph
                (GitHub issue #1372). Every other object is expanded in full
                each time it is met, except one that encloses itself: there
                it is written as a ``<circular reference: ...>`` marker, so a
                reference cycle terminates.

            Raises:
                UnsupportedCall: If a top-level fallback object expands into
                    more than :data:`FALLBACK_LIMIT` objects.

            """
            if isinstance(value, (type, types.ModuleType)) or inspect.isroutine(value):
                self._append_fallback_value(_object_name(value), file)
                return

            path = self._fallback_path
            if path is None:
                # NOTE: the outermost fallback object owns the bookkeeping, so
                # each record dumped is tracked on its own.
                self._fallback_path, self._fallback_count = set(), 0
                try:
                    self._append_fallback(value, file)
                finally:
                    self._fallback_path, self._fallback_count = None, 0
                return

            # NOTE: an object on the path is alive, so its id is not reused.
            key = id(value)
            if key in path:
                marker = f'<circular reference: {_object_name(type(value))}>'
                self._append_fallback_value(marker, file)
                return
            self._fallback_count += 1
            if self._fallback_count > FALLBACK_LIMIT:
                raise UnsupportedCall(f'{type(self).__name__}: fallback object expands into more '
                                      f'than {FALLBACK_LIMIT} objects; stopped at '
                                      f'{_object_name(type(value))}')
            path.add(key)
            try:
                new_value = {name: getattr(value, name) for name in _iter_slots(value)}
                if hasattr(value, '__dict__'):
                    new_value.update(vars(value))
                if not new_value:
                    logger.warning('unsupported object type: %s', type(value))
                    new_value = str(value)  # type: ignore[assignment]
                self._append_fallback_value(new_value, file)
            finally:
                path.discard(key)

        def _append_fallback_value(self, value: 'Any', file: 'TextIO') -> 'None':
            """Write what :meth:`_append_fallback` made of an object.

            Args:
                self: Dumper instance.
                value: Value to dump in place of the object.
                file: File object to write.

            """
            # NOTE: through :meth:`object_hook` as every other value is, so that
            # the keys and strings built here are escaped like theirs.
            value = self.object_hook(value)
            func = self._encode_func(value)
            func(value, file)

    return DictDumper
