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
import tempfile
from typing import TYPE_CHECKING

import aenum
import dictdumper.dumper

from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.logging import logger

__all__ = ['make_dumper']

if TYPE_CHECKING:
    from typing import Any, DefaultDict, Optional, TextIO, Type

    from dictdumper.dumper import Dumper as ABCDumper
    from typing_extensions import Literal


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
    for automatic registration to the
    :class:`~pcapkit.foundation.extraction.Extractor` and
    :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` output
    dumper registries.

    """

    def __init_subclass__(cls, /, fmt: 'Optional[str]' = None,
                          ext: 'Optional[str]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialise subclass.

        This method is used to register the subclass to the
        :class:`~pcapkit.foundation.extraction.Extraction` and
        :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow`
        output dumper registries.

        Args:
            fmt: Output format to register.
            ext: Output file extension.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        If the ``fmt`` is not provided, we will try to get it from the
        :attr:`~dictdumper.dumper.Dumper.kind` property of the subclass.
        And if the ``ext`` is not provided, we will infer it from the
        ``fmt``.

        See Also:
            - :func:`pcapkit.foundation.registry.foundation.register_dumper`
            - :func:`pcapkit.foundation.registry.foundation.register_extractor_dumper`
            - :func:`pcapkit.foundation.registry.foundation.register_traceflow_dumper`
            - :meth:`pcapkit.foundation.extraction.Extractor.register_dumper`
            - :meth:`pcapkit.foundation.traceflow.traceflow.TraceFlow.register_dumper`

        """
        if fmt is None:
            with tempfile.NamedTemporaryFile() as temp:
                fmt = cls(temp.name).kind
        fmt = fmt.lower()

        if ext is None:
            ext = f'.{fmt}'

        from pcapkit.foundation.extraction import Extractor
        Extractor.register_dumper(fmt, cls, ext)

        from pcapkit.foundation.traceflow.traceflow import TraceFlow
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
