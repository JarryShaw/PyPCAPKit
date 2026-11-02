# -*- coding: utf-8 -*-
"""Radiotap L-SIG Data1 Flags
================================

.. module:: pcapkit.vendor.radiotap.lsig_data1

This module contains the vendor crawler for **Radiotap L-SIG Data1 Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.lsig_data1.LSIGData1`.

The registry is the bits of the L-SIG field's ``data1``, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['LSIGData1']


class LSIGData1(Flags):
    """Radiotap L-SIG Data1 Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/L-SIG.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'data1'
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x0001: 'IEEE80211_RADIOTAP_LSIG_DATA1_RATE_KNOWN',
        0x0002: 'IEEE80211_RADIOTAP_LSIG_DATA1_LENGTH_KNOWN',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(LSIGData1())  # type: ignore[arg-type]
