# -*- coding: utf-8 -*-
"""Radiotap Timestamp Flags
==============================

.. module:: pcapkit.vendor.radiotap.timestamp_flags

This module contains the vendor crawler for **Radiotap Timestamp Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.timestamp_flags.TimestampFlags`.

The registry is the bits of the timestamp field's ``flags``, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['TimestampFlags']


class TimestampFlags(Flags):
    """Radiotap Timestamp Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/timestamp.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'flags'
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x01: 'IEEE80211_RADIOTAP_TIMESTAMP_FLAG_32BIT',
        0x02: 'IEEE80211_RADIOTAP_TIMESTAMP_FLAG_ACCURACY',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(TimestampFlags())  # type: ignore[arg-type]
