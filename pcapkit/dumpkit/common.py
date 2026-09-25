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
import ipaddress
import xml.sax.saxutils
from typing import TYPE_CHECKING

import aenum
import dictdumper.dumper
import dictdumper.plist

from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import UnsupportedCall
from pcapkit.utilities.logging import get_logger

__all__ = ['make_dumper']


if TYPE_CHECKING:
    from typing import Any, DefaultDict, Optional, TextIO, Type

    from dictdumper.dumper import Dumper as ABCDumper
    from typing_extensions import Literal


#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


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
        has guarded on its own ``code`` keyword all along.

        Note:
            The previous behaviour inferred ``fmt`` from the subclass'
            :attr:`~dictdumper.dumper.Dumper.kind` property, which it could
            only read off an *instance* -- so it constructed one against a
            :func:`tempfile.NamedTemporaryFile` while the ``class`` statement
            was still executing. Guarding on ``fmt`` removes that: a class
            definition no longer touches the filesystem.

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
        so interpolating it unguarded put the literal four characters ``None``
        into the name half and rendered
        :class:`~pcapkit.const.tcp.flags.Flags` ``(0)`` as ``'Flags::None [0]'``
        (GitHub issue #648).

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
        begin with a digit -- none of the 1867 identifiers declared under
        :mod:`pcapkit.const` is a bare decimal, and none ever can be.

        This is *not* an :mod:`aenum` quirk. A stdlib :class:`enum.IntFlag` built
        from the same members answers ``name is None`` identically on CPython
        3.14.7, so the guard belongs here rather than in a choice of enumeration
        library.

    """
    name = o.name
    if name is None:
        name = str(o.value)
    return f'{type(o).__name__}::{name} [{o.value}]'


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
    # concrete writer this applies to today.
    escape_strings = issubclass(output, dictdumper.plist.PLIST)

    class DictDumper(output):
        """Customised :class:`~dictdumper.dumper.Dumper` object."""

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
                one exception is a :class:`~pcapkit.corekit.multidict.MultiDict`
                key: :meth:`~dictdumper.dumper.Dumper._append_dict` writes a
                dict's keys straight from the mapping without ever calling
                this method on them, so a key built from :func:`render_enum`
                is escaped inline, right where it is built, instead.

            """
            if isinstance(o, decimal.Decimal):
                result = str(o)  # type: Any
            elif isinstance(o, datetime.timedelta):
                result = o.total_seconds()
            elif isinstance(o, (Info, Schema)):
                result = o.to_dict()
            elif isinstance(o, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                result = str(o)
            elif isinstance(o, (MultiDict, OrderedMultiDict)):
                temp = collections.defaultdict(list)  # type: DefaultDict[str, list[Any]]
                for key, val in o.items(multi=True):
                    if isinstance(key, (enum.Enum, aenum.Enum)):
                        key = render_enum(key)
                        if escape_strings:
                            key = xml.sax.saxutils.escape(key)
                    temp[key].append(val)
                result = temp
            elif isinstance(o, dict):
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
                return xml.sax.saxutils.escape(result)
            return result

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

            """
            if hasattr(value, '__slots__'):
                new_value = {key: getattr(value, key) for key in value.__slots__}
            elif hasattr(value, '__dict__'):
                new_value = vars(value)
            else:
                logger.warning('unsupported object type: %s', type(value))
                new_value = str(value)  # type: ignore[assignment]

            func = self._encode_func(new_value)
            func(new_value, file)

    return DictDumper
