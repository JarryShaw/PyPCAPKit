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
from typing import TYPE_CHECKING

import aenum
import dictdumper.dumper

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


def make_dumper(output: 'Type[ABCDumper]') -> 'Type[ABCDumper]':
    """Create a customised :class:`~dictdumper.dumper.Dumper` object.

    Args:
        output: Output class to customise.

    Returns:
        Customised :class:`~dictdumper.dumper.Dumper` object.

    """
    class DictDumper(output):
        """Customised :class:`~dictdumper.dumper.Dumper` object."""

        def object_hook(self, o: 'Any') -> 'Any':
            """Convert content for function call.

            Args:
                self: Dumper instance.
                o: object to convert

            Returns:
                Converted object.

            """
            if isinstance(o, decimal.Decimal):
                return str(o)
            if isinstance(o, datetime.timedelta):
                return o.total_seconds()
            if isinstance(o, (Info, Schema)):
                return o.to_dict()
            if isinstance(o, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                return str(o)
            if isinstance(o, (MultiDict, OrderedMultiDict)):
                temp = collections.defaultdict(list)  # type: DefaultDict[str, list[Any]]
                for key, val in o.items(multi=True):
                    if isinstance(key, (enum.Enum, aenum.Enum)):
                        key = f'{type(key).__name__}::{key.name} [{key.value}]'
                    temp[key].append(val)
                return temp
            if isinstance(o, dict):
                return o
            if isinstance(o, (enum.Enum, aenum.Enum)):
                addon = {key: val for key, val in o.__dict__.items() if not key.startswith('_')}
                if addon:
                    return {
                        'enum': f'{type(o).__name__}::{o.name} [{o.value}]',
                        **addon,
                    }
                return f'{type(o).__name__}::{o.name} [{o.value}]'
            return super(type(self), self).object_hook(o)  # type: ignore[unreachable]

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
                :func:`pcapkit.dumpkit.common._append_fallback` for use.

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
                :func:`pcapkit.dumpkit.common.default` for use.

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
