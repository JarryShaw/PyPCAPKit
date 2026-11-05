# -*- coding: utf-8 -*-
"""Timestamp Conversion
==========================

.. module:: pcapkit.utilities.datetime

:mod:`pcapkit.utilities.datetime` converts a UNIX timestamp to an aware
:class:`~datetime.datetime` without the C library's range (:issue:`2099`), and
a :class:`~datetime.datetime` back to a UNIX timestamp without GraalPy's lost
second before 1970 (:issue:`2134`).

"""

import datetime
import math
import operator
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import tzinfo

__all__ = ['fromtimestamp', 'totimestamp']

# Avoids the platform ``gmtime()``, narrower than ``datetime``'s on Windows (#2099).
# ``fromtimestamp`` splits a float as CPython does (``math.modf``, the fraction
# times ``1e6`` rounded half to even, carried into ``[0, 1e6)``) on every
# interpreter, so every instant gets glibc ``gmtime_r``'s result. Its
# errors are CPython's on 64-bit Linux, except past a C ``int`` year (about 6.7e16
# seconds), where CPython raises ``OSError`` and this ``ValueError``. On GraalPy,
# a ``tz`` offset out of range raises ``ValueError`` from its ``fromutc`` (#2134).
_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
#: First and last whole second since the UNIX epoch in years 1 to 9999.
_EPOCH_MIN = -62_135_596_800
_EPOCH_MAX = 253_402_300_799
#: Microseconds per second, the resolution of :class:`~datetime.datetime`.
_MICROSECONDS = datetime.timedelta(seconds=1) // datetime.timedelta(microseconds=1)
#: A 64-bit ``time_t`` holds ``[-_TIME_T, _TIME_T)``.
_TIME_T = 2**63

# GraalPy 25.4.4 truncates an aware datetime's whole seconds toward zero, so
# 23:59:59.5 on 1969-12-31 UTC gives ``0.5``, not ``-0.5`` (#2134): its
# ``TimestampNode`` uses ``ChronoUnit.SECONDS.between`` (DateTimeBuiltins.java,
# no upstream issue filed). Elsewhere ``totimestamp`` is the stdlib call itself.
_TIMESTAMP_TRUNCATES = sys.implementation.name == 'graalpy'


def fromtimestamp(timestamp: 'float | int', tz: 'tzinfo') -> 'datetime.datetime':
    """:meth:`datetime.datetime.fromtimestamp` with a ``tz``, minus the C library's range.

    The result equals ``datetime.datetime.fromtimestamp(timestamp, tz)`` on
    64-bit Linux for every ``timestamp`` that call accepts, on every platform:
    whole seconds and microseconds split from a float as CPython splits them,
    rounding half to even, then added to the UNIX epoch and rendered in ``tz``.
    The standard library breaks the instant down with the C library's
    ``gmtime()``, whose range on Windows is 1970 to 3000, so there it raises
    :exc:`OSError` for instants :class:`~datetime.datetime` holds.

    Args:
        timestamp: Seconds since the UNIX epoch.
        tz: Timezone the result is rendered in.

    Returns:
        The instant ``timestamp`` names, rendered in ``tz``.

    Raises:
        ValueError: If ``timestamp`` is NaN, or names a year outside 1 to 9999.
        OverflowError: If ``timestamp`` is past a 64-bit ``time_t``, or ``tz``
            moves the result out of the range :class:`~datetime.datetime` holds.

    .. versionadded:: 1.5.0

       Every capture and MH timestamp is converted with it (:issue:`2099`).

    """
    if isinstance(timestamp, float):
        if math.isnan(timestamp):
            raise ValueError('Invalid value NaN (not a number)')
        frac, whole = math.modf(timestamp)
        # ``round`` of a float is half to even; the carry is -1, 0 or 1
        carry, micro = divmod(round(frac * _MICROSECONDS), _MICROSECONDS)
        whole += carry
    else:
        whole, micro = operator.index(timestamp), 0
    if not -_TIME_T <= whole < _TIME_T:
        raise OverflowError('timestamp out of range for platform time_t')
    seconds = int(whole)
    if not _EPOCH_MIN <= seconds <= _EPOCH_MAX:
        raise ValueError(f'year is out of range for timestamp {timestamp!r}')
    utc = _EPOCH + datetime.timedelta(seconds=seconds, microseconds=micro)
    return tz.fromutc(utc.replace(tzinfo=tz))


def totimestamp(dt: 'datetime.datetime') -> 'float':
    """:meth:`datetime.datetime.timestamp`, as CPython computes it, on every interpreter.

    For an aware ``dt`` that is ``(dt - epoch).total_seconds()``. GraalPy's own
    counts the whole seconds toward zero, so there an instant before 1970 with a
    fraction of a second comes out one second late, and this computes it as
    CPython does. A naive ``dt`` is local time, and is ``dt.timestamp()``
    everywhere.

    Args:
        dt: Moment to convert.

    Returns:
        Seconds since the UNIX epoch.

    .. versionadded:: 1.5.0

       The PCAP and PCAP-NG writers and the MH replay protection option convert
       a :class:`~datetime.datetime` with it (:issue:`2134`).

    """
    if _TIMESTAMP_TRUNCATES and dt.tzinfo is not None:
        return (dt - _EPOCH).total_seconds()
    return dt.timestamp()
