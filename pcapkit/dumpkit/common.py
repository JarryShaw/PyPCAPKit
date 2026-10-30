# -*- coding: utf-8 -*-
"""Common Utilities
======================

.. module:: pcapkit.dumpkit.common

:mod:`pcapkit.dumpkit.common` is the collection of common utility
functions for :mod:`pcapkit.dumpkit` implementation, which is
generally the customised hooks for :class:`dictdumper.dumper.Dumper`
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
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import UnsupportedCall
from pcapkit.utilities.logging import get_logger

__all__ = ['make_dumper']


if TYPE_CHECKING:
    from typing import Any, Collection, DefaultDict, Iterator, Optional, TextIO, Type

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
        writes every output registry, so the equivalent manual call is the
        module-level one that does the same, not any one class' own method:

        .. code-block:: python

           from pcapkit.foundation.registry.foundation import register_dumper

           register_dumper('my_mixin', MyMixin, ext='.mine')

    .. versionchanged:: 1.5.0

       Registration is opt-in, under the ``fmt`` class keyword; 1.4.x
       registered every subclass, under its
       :attr:`~dictdumper.dumper.Dumper.kind` when the keyword was omitted
       (:issue:`514`).

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
        # NOTE: as in the sibling hooks, an unrecognised class keyword would
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
    one function rather than being spelled out at each place
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

        That is worth a guard rather than a shrug. ``'None'`` is a
        plausible member name, so a consumer splitting the rendering on ``::``
        cannot tell it from a member genuinely so named -- and ``NONE`` *is* a
        declared name elsewhere in the library. And the defect is not confined to
        zero: a registry whose field has undeclared bits, such as
        :class:`~pcapkit.const.mh.binding_update_flag.BindingUpdateFlag`, is
        every bit as nameless at ``1`` or ``8``, so a guard written against
        ``value == 0`` would fix one case and leave the rest.

        The fallback is the value's own decimal spelling, which is what the
        enumeration libraries themselves already use for an undeclared residue:
        ``BindingUpdateFlag(32777).name`` is ``'A|9'``, naming the declared bit
        and giving the leftovers as one number. A wholly-undeclared value is that
        same rendering with no declared bit to precede it, so
        ``BindingUpdateFlag(9)`` becomes ``'BindingUpdateFlag::9 [9]'`` and
        ``Flags(0)`` becomes ``'Flags::0 [0]'``. It also
        cannot be mistaken for a member name, since a Python identifier may not
        begin with a digit.

        This is *not* an |aenum|_ quirk. A stdlib :class:`enum.IntFlag` built
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


def _surrogate_pairs(text: 'str') -> 'str':
    """Split every character above ``U+FFFF`` in ``text`` into its UTF-16 surrogate pair.

    Args:
        text: Text to split.

    Returns:
        ``text`` with each astral character (above ``U+FFFF``) replaced by the
        two lone-surrogate code points :func:`json.dumps` would write it as;
        every other character is returned unchanged.

    Note:
        This is for :mod:`dictdumper.json`'s *key* path, which escapes a
        mapping key through its module-level :func:`~dictdumper.json.encode_string`
        directly rather than through an overridable method (GitHub issue
        :issue:`1261`). That function already escapes a lone surrogate as a
        four-digit ``\\uXXXX`` sequence -- it is only a *pair* of code points
        above ``U+FFFF`` it cannot spell -- so splitting first and handing it
        the pair is enough; no change to :func:`~dictdumper.json.encode_string`
        itself is needed.

    """
    chars = []  # type: list[str]
    for char in text:
        codepoint = ord(char)
        if codepoint > 0xFFFF:
            codepoint -= 0x10000
            chars.append(chr(0xD800 + (codepoint >> 10)))
            chars.append(chr(0xDC00 + (codepoint & 0x3FF)))
        else:
            chars.append(char)
    return ''.join(chars)


def make_dumper(output: 'Type[ABCDumper]') -> 'Type[ABCDumper]':
    """Create a customised :class:`~dictdumper.dumper.Dumper` class.

    Args:
        output: Output class to customise.

    Returns:
        Customised :class:`~dictdumper.dumper.Dumper` subclass of ``output``.

    .. versionchanged:: 1.5.0

       Several dumped shapes change. A nameless flag value renders its value
       as the name, ``Flags::0 [0]`` rather than ``Flags::None [0]``
       (:issue:`648`). An :class:`~pcapkit.corekit.multidict.OrderedMultiDict`
       dumps as a list of one-key mappings in wire order, not grouped by key
       (:issue:`1263`). An :class:`~ipaddress.IPv4Network` or
       :class:`~ipaddress.IPv6Network` dumps as its string, a timezone as its
       offset in seconds, and :data:`~pcapkit.corekit.sentinels.NULL` and
       :data:`~pcapkit.corekit.sentinels.NO_VALUE` as ``'<NULL>'`` and
       ``'<NO_VALUE>'`` (:issue:`1258`). In ``plist`` output, :data:`None` is
       kept (:issue:`1257`), and a string carrying a character XML forbids
       is written as ``<data>`` (:issue:`1262`).

    """
    # NOTE: :class:`~dictdumper.plist.PLIST` -- which is also what
    # :attr:`Extractor.__output__ <pcapkit.foundation.extraction.Extractor.__output__>`
    # maps the ``'xml'`` format to, so the two are the same writer under two
    # names here -- used to interpolate every ``<string>``/``<key>`` value into
    # its XML-shaped markup with no entity escaping at all: neither ``&``,
    # ``<`` nor ``>`` was escaped anywhere in :mod:`dictdumper`. Filed upstream
    # as JarryShaw/DictDumper#125 and tracked here as GitHub issue #772 -- along
    # with the sibling ``json`` key-quoting defect, DictDumper#121 -- and both
    # halves are now fixed upstream in ``dictdumper`` 0.8.5 (DictDumper#123):
    # :func:`dictdumper.plist.encode_xml` and :func:`dictdumper.json.encode_string`
    # each escape a mapping key exactly as they escape the value beside it, so
    # the escaping this module used to do for both is removed rather than
    # doubled up on top of the upstream fix.
    #
    # ``is_plist_output`` survives under its own name for two narrower,
    # still-unfixed reasons: a string holding a character XML 1.0 cannot spell
    # at all (GitHub issue #1262, below) still has to be written as
    # :class:`bytes` instead, and an aware :class:`~datetime.datetime` still has
    # to be converted to UTC before the (now upstream-fixed) ``<date>``
    # formatting runs, which neither :mod:`dictdumper` nor
    # :func:`plistlib.dump` does on its own (GitHub issue #1448, below).
    is_plist_output = issubclass(output, dictdumper.plist.PLIST)
    # NOTE: :meth:`~dictdumper.json.JSON._append_string` and the module-level
    # :func:`dictdumper.json.encode_string` it shares with
    # :meth:`~dictdumper.json.JSON._append_object` both escape a character
    # above ``U+FFFF`` as a single five- or six-digit ``\uXXXX`` escape, which a
    # reader takes as one four-digit escape followed by literal text (GitHub
    # issue #1261). Unlike the key-escaping defect above, ``dictdumper`` 0.8.5
    # left this one alone -- confirmed by reading the installed package's
    # :func:`dictdumper.json.encode_string` -- so the surrogate-pair workarounds
    # on :meth:`DictDumper._append_string` (values) and
    # :meth:`DictDumper._append_object` (keys) below still apply.
    is_json_output = issubclass(output, dictdumper.json.JSON)
    # NOTE: :meth:`~dictdumper.plist.PLIST._append_dict` and
    # :meth:`~dictdumper.plist.PLIST._append_array` skip every :data:`None`
    # value and item outright, so a ``plist`` report lacks keys the ``json``
    # report has (GitHub issue #1257). The defect is :mod:`dictdumper`'s, and
    # ``dictdumper`` 0.8.5 did not touch it, so it is still worked around here.
    keep_none = issubclass(output, dictdumper.plist.PLIST)
    # NOTE: :meth:`~dictdumper.tree.Tree._append_number` hands every number to
    # :func:`math.isnan`, which raises :exc:`TypeError` for a :class:`complex`
    # one, although :class:`~dictdumper.tree.Tree` routes :class:`complex` there
    # (GitHub issue #1266). The defect is :mod:`dictdumper`'s, and ``dictdumper``
    # 0.8.5 did not touch it, so it is still worked around here.
    tree_numbers = issubclass(output, dictdumper.tree.Tree)

    def excluded(info: 'Info | MultiDict[Any, Any]') -> 'Collection[Any]':
        """Return the keys of ``info`` the writer leaves out.

        Args:
            info: An :class:`~pcapkit.corekit.infoclass.Info`, or a multi-mapping
                such as the export its :meth:`~pcapkit.corekit.infoclass.Info.to_dict`
                returns.

        Returns:
            The :attr:`~pcapkit.corekit.infoclass.Info.__excluded__` of a field
            model, or of the field model an export was made from -- metadata
            such as ``__next_type__``, which only a rebuild reads
            (:issue:`2003`). Empty for an option list, whose keys are its
            options.

        """
        if isinstance(info, Info) and isinstance(info, MultiDict):
            return ()
        return getattr(info, '__excluded__', ())

    def fields(info: 'Info | MultiDict[Any, Any]') -> 'dict[Any, Any]':
        """Return the fields of ``info`` as the :class:`dict` the writer is handed.

        Args:
            info: The fields, as an :class:`~pcapkit.corekit.infoclass.Info` or
                as the :class:`~pcapkit.corekit.multidict.OrderedMultiDict` its
                :meth:`~pcapkit.corekit.infoclass.Info.to_dict` returns.

        Returns:
            One entry per field, in order, with its key unchanged -- the writer
            itself now escapes a mapping key where ``output`` needs that
            (``dictdumper`` 0.8.5, DictDumper#123). A field held once maps to
            its value; a field held more than once, such as a repeated IPv6
            extension header, maps to the :class:`list` of all its values, in
            order (GitHub issue :issue:`1484`). The values are left as they
            are, so each comes back through :meth:`DictDumper.object_hook` when
            written. The keys :func:`excluded` names are left out.

        """
        skip = excluded(info)
        pairs = [(key, val) for key, val in info.items(multi=True) if key not in skip]
        counts = collections.Counter(key for key, _ in pairs)
        result = {}  # type: dict[Any, Any]
        for key, val in pairs:
            if counts[key] > 1:
                result.setdefault(key, []).append(val)
            else:
                # NOTE: read by indexing, so that a model overriding it is
                # honoured -- the traceflow and reassembly models resolve a
                # deferred ``packet`` there.
                result[key] = info[key]
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
                Converted object. Escaping a string or a mapping key for
                XML-shaped output is the writer's own job since ``dictdumper``
                0.8.5 (DictDumper#123); this method no longer does it.

            Notes:
                :meth:`~dictdumper.dumper.Dumper._encode_value` -- and so this
                method -- is called once per node the dumper writes, however
                deeply nested. A mapping *key* never reaches this method at
                all: :meth:`~dictdumper.plist.PLIST._append_dict` and
                :meth:`~dictdumper.json.JSON._append_object` write a key
                straight from the mapping, and now escape it themselves where
                ``output`` needs that, exactly as they escape the value beside
                it. An :class:`~pcapkit.corekit.multidict.OrderedMultiDict`
                becomes a :class:`list` of single-key :class:`dict` objects,
                each of which comes back through the :class:`dict` branch, and
                so does an :class:`~pcapkit.corekit.infoclass.OrderedMultiInfo`,
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
                # occurrence (GitHub issue #1263). Each single-key mapping comes
                # back through the :class:`dict` branch below, which is where the
                # writer itself now escapes the key, where ``output`` needs that.
                # The keys an export of an :class:`Info` excludes are left out,
                # as :func:`fields` leaves them out (#2003).
                skip = excluded(o)
                result = [
                    {render_enum(key) if isinstance(key, (enum.Enum, aenum.Enum)) else key: val}
                    for key, val in o.items(multi=True) if key not in skip
                ]
            elif isinstance(o, MultiDict):
                # NOTE: a :class:`MultiDict` keeps no order across keys, only
                # among the values of each, so grouping by key loses nothing.
                temp = collections.defaultdict(list)  # type: DefaultDict[str, list[Any]]
                for key, val in o.items(multi=True):
                    if isinstance(key, (enum.Enum, aenum.Enum)):
                        key = render_enum(key)
                    temp[key].append(val)
                result = temp
            elif isinstance(o, dict):
                # NOTE: never rebuilt -- the writer now escapes a key itself
                # where ``output`` needs that (``dictdumper`` 0.8.5,
                # DictDumper#123), so every output is handed the caller's own
                # mapping, with the caller's own key objects in it.
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
                result = super().object_hook(o)

            # NOTE: XML 1.0 has no spelling at all for some characters, not
            # even a character reference, so a PLIST string holding one is
            # written as ``<data>``, the way :class:`bytes` already is (GitHub
            # issue #1262). Any escaping the string itself still needs --
            # ``&``, ``<`` and ``>`` -- is now the writer's own job.
            if is_plist_output and isinstance(result, str) and _XML_ILLEGAL.search(result) is not None:
                return result.encode('utf-8', 'surrogatepass')
            return result

        if is_plist_output:
            def _append_date(self, value: 'datetime.date', file: 'TextIO') -> 'None':
                """Call this function to write date contents.

                Args:
                    self: Dumper instance.
                    value: Content to be dumped.
                    file: Output file.

                Notes:
                    An aware value is converted to UTC first, a naive one is
                    taken as UTC already -- neither :mod:`dictdumper` nor
                    :func:`plistlib.dump` (without its 3.13+ ``aware_datetime``
                    flag) does this conversion on its own, so it stays pcapkit's
                    own addition on top of the upstream writer. The exact value
                    is not lost: every timestamp pcapkit reports sits next to a
                    field that carries it exactly -- a :class:`~decimal.Decimal`
                    ``*_epoch`` for frames and PCAP-NG blocks and options, e.g.
                    ``time_epoch``, and the raw ``ntp_timestamp`` or
                    ``pmip_timestamp`` for the MH options that carry one.

                    Formatting to whole seconds -- the property list ``<date>``
                    grammar has no fractional part (GitHub issue :issue:`1448`) -- is now
                    :meth:`~dictdumper.plist.PLIST._append_date`'s own job, fixed
                    upstream in ``dictdumper`` 0.8.5 (DictDumper#124), so it is
                    left to :meth:`super`.

                """
                if isinstance(value, datetime.datetime) and value.tzinfo is not None:
                    value = value.astimezone(datetime.timezone.utc)
                super()._append_date(value, file)

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
                    so that the writer does not skip it.

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

        if is_json_output:
            def _append_object(self, value: 'dict[Any, Any]', file: 'TextIO') -> 'None':
                """Call this function to write object (mapping) contents.

                Args:
                    self: Dumper instance.
                    value: Content to be dumped.
                    file: Output file.

                Notes:
                    :meth:`dictdumper.json.JSON._append_object` escapes each key
                    through the module-level :func:`dictdumper.json.encode_string`
                    directly, not through :meth:`_append_string`, so the
                    surrogate-pair handling there never reaches a key -- a
                    :class:`str` key holding a character above ``U+FFFF`` is
                    still written as the single five- or six-digit escape
                    :func:`~dictdumper.json.encode_string` always wrote (GitHub
                    issue :issue:`1261`). Splitting such a key into its UTF-16
                    surrogate pair first, with :func:`_surrogate_pairs`, makes
                    :func:`~dictdumper.json.encode_string` emit the same pair of
                    four-digit escapes it already writes for a lone surrogate,
                    matching what :func:`json.dumps` writes and what
                    :meth:`_append_string` above already does for a value.

                """
                if any(isinstance(key, str) and any(ord(char) > 0xFFFF for char in key)
                       for key in value):
                    value = {
                        _surrogate_pairs(key) if isinstance(key, str) else key: val
                        for key, val in value.items()
                    }
                super()._append_object(value, file)

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
                    (GitHub issue :issue:`1261`). This writes such a character as a
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
                (GitHub issue :issue:`1372`). Every other object is expanded in full
                each time it is met, except one that encloses itself: there
                it is written as a ``<circular reference: ...>`` marker, so a
                reference cycle terminates.

            Raises:
                UnsupportedCall: If a top-level fallback object expands into
                    more than :data:`~pcapkit.utilities.config.FALLBACK_LIMIT` objects.

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
            limit = config.FALLBACK_LIMIT
            if limit != -1 and self._fallback_count > limit:
                raise UnsupportedCall(f'{type(self).__name__}: fallback object expands into more '
                                      f'than {limit} objects; stopped at '
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
