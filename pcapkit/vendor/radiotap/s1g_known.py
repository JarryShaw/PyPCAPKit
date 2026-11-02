# -*- coding: utf-8 -*-
"""Radiotap S1G Known Flags
==============================

.. module:: pcapkit.vendor.radiotap.s1g_known

This module contains the vendor crawler for **Radiotap S1G Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.s1g_known.S1GKnown`.

The registry is the bits of the S1G field's ``known``, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['S1GKnown']


class S1GKnown(Flags):
    """Radiotap S1G Known Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/S1G.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'known'
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x0001: 'IEEE80211_RADIOTAP_S1G_KNOWN_PPDU_FORMAT',
        0x0002: 'IEEE80211_RADIOTAP_S1G_KNOWN_RESPONSE_IND',
        0x0004: 'IEEE80211_RADIOTAP_S1G_KNOWN_GI',
        0x0008: 'IEEE80211_RADIOTAP_S1G_KNOWN_NSS',
        0x0010: 'IEEE80211_RADIOTAP_S1G_KNOWN_BW',
        0x0020: 'IEEE80211_RADIOTAP_S1G_KNOWN_MCS',
        0x0040: 'IEEE80211_RADIOTAP_S1G_KNOWN_COLOR',
        0x0080: 'IEEE80211_RADIOTAP_S1G_KNOWN_UPLINK_IND',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(S1GKnown())  # type: ignore[arg-type]
