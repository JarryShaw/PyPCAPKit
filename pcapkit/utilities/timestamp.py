# -*- coding: utf-8 -*-
"""Timestamp Conversion
======================

.. module:: pcapkit.utilities.timestamp

:mod:`pcapkit.utilities.timestamp` converts a UNIX timestamp to an aware
:class:`~datetime.datetime` without the C library's range (:issue:`2099`).

"""

import datetime
import math
import operator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import tzinfo

__all__ = ['fromtimestamp']

# A UNIX timestamp as an aware datetime, without the C library (#2099).
# :meth:`datetime.datetime.fromtimestamp` breaks the instant down with the
# platform's ``gmtime()`` when given a ``tz``, so its range is the C library's
# rather than ``datetime``'s: the Windows CRT's ``gmtime_s`` takes no time before
# 1970 and none after 3000, and CPython raises :exc:`OSError` there for instants
# ``datetime`` holds. This splits a float into whole seconds and microseconds
# exactly as CPython does -- :func:`math.modf`, the fraction times ``1e6``
# rounded half to even, then carried into ``[0, 1e6)`` -- and adds them to the
# epoch, so every instant gets the result glibc's ``gmtime_r`` gives. It is not
# a version gate: the same arithmetic runs on every interpreter.
#
# The errors are CPython's on 64-bit Linux, by class: :exc:`ValueError` for NaN
# or a year outside 1 to 9999, and :exc:`OverflowError` for whole seconds past
# a 64-bit ``time_t`` or a ``tz`` offset that pushes the result out of range.
# The one exception is a year past what a C ``int`` holds, from about 6.7e16
# seconds, where glibc's own ``gmtime_r`` fails first and CPython raises
# :exc:`OSError` instead; this raises :exc:`ValueError` there too.
_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
#: First and last whole second since the UNIX epoch in years 1 to 9999.
_EPOCH_MIN = -62_135_596_800
_EPOCH_MAX = 253_402_300_799
#: Microseconds per second, the resolution of :class:`~datetime.datetime`.
_MICROSECONDS = datetime.timedelta(seconds=1) // datetime.timedelta(microseconds=1)
#: A 64-bit ``time_t`` holds ``[-_TIME_T, _TIME_T)``.
_TIME_T = 2**63


def fromtimestamp(timestamp: 'float | int', tz: 'tzinfo') -> 'datetime.datetime':
    """:meth:`datetime.datetime.fromtimestamp` with a ``tz``, minus the C library's range.

    The result equals ``datetime.datetime.fromtimestamp(timestamp, tz)`` on
    64-bit Linux for every ``timestamp`` that call accepts, on every platform.

    Args:
        timestamp: Seconds since the UNIX epoch.
        tz: Timezone the result is rendered in.

    Raises:
        ValueError: If ``timestamp`` is NaN, or names a year outside 1 to 9999.
        OverflowError: If ``timestamp`` is past a 64-bit ``time_t``, or ``tz``
            moves the result out of the range :class:`~datetime.datetime` holds.

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
