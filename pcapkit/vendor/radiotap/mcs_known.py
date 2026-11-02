# -*- coding: utf-8 -*-
"""Radiotap MCS Known Flags
==============================

.. module:: pcapkit.vendor.radiotap.mcs_known

This module contains the vendor crawler for **Radiotap MCS Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.mcs_known.MCSKnown`.

The registry is the bits of the MCS field's ``known``, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['MCSKnown']


class MCSKnown(Flags):
    """Radiotap MCS Known Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/MCS.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'known'
    #: The source macro of each bit, keyed by mask, which is Linux's, and
    #: Wireshark's ``packet-ieee80211-radiotap-defs.h`` for ``0x40`` and
    #: ``0x80``, which Linux leaves unnamed.
    NAMES = {
        0x01: 'IEEE80211_RADIOTAP_MCS_HAVE_BW',
        0x02: 'IEEE80211_RADIOTAP_MCS_HAVE_MCS',
        0x04: 'IEEE80211_RADIOTAP_MCS_HAVE_GI',
        0x08: 'IEEE80211_RADIOTAP_MCS_HAVE_FMT',
        0x10: 'IEEE80211_RADIOTAP_MCS_HAVE_FEC',
        0x20: 'IEEE80211_RADIOTAP_MCS_HAVE_STBC',
        0x40: 'IEEE80211_RADIOTAP_MCS_HAVE_NESS',
        0x80: 'IEEE80211_RADIOTAP_MCS_NESS_BIT1',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(MCSKnown())  # type: ignore[arg-type]
