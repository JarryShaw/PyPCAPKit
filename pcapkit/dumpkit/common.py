# -*- coding: utf-8 -*-
"""Common Utilities
======================

.. module:: pcapkit.dumpkit.common

:mod:`pcapkit.dumpkit.common` is the collection of common utility
functions for :mod:`pcapkit.dumpkit` implementation, which is
generally the customised hooks for :class:`dictdumper.Dumper`
classes.

"""
import datetime
import decimal
import enum
import ipaddress
from typing import TYPE_CHECKING

import aenum

from pcapkit.corekit.infoclass import Info
from pcapkit.utilities.logging import logger

__all__ = ['object_hook', 'default', '_append_fallback']

if TYPE_CHECKING:
    from typing import Any, TextIO

    from dictdumper.dumper import Dumper
    from typing_extensions import Literal


def object_hook(self: 'Dumper', o: 'Any') -> 'Any':
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
    if isinstance(o, Info):
        return o.to_dict()
    if isinstance(o, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(o)
    if isinstance(o, (enum.Enum, aenum.Enum)):
        addon = {key: val for key, val in o.__dict__.items() if not key.startswith('_')}
        return dict(
            name=f'{type(o).__name__}::{o.name}',
            value=o.value,
            **addon,
        )
    return super(type(self), self).object_hook(o)  # type: ignore[unreachable]


def default(self: 'Dumper', o: 'Any') -> 'Literal["fallback"]':  # pylint: disable=unused-argument
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


def _append_fallback(self: 'Dumper', value: 'Any', file: 'TextIO') -> 'None':
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
