# -*- coding: utf-8 -*-
"""Radiotap A-MPDU Status Flags
==================================

.. module:: pcapkit.vendor.radiotap.ampdu_flags

This module contains the vendor crawler for **Radiotap A-MPDU Status Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.ampdu_flags.AMPDUFlags`.

The registry is the bits of the A-MPDU status field's ``flags``, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['AMPDUFlags']


class AMPDUFlags(Flags):
    """Radiotap A-MPDU Status Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/A-MPDU%20status.html'
    #: Subfield whose table is scraped.
    SUBFIELD = None
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x0001: 'IEEE80211_RADIOTAP_AMPDU_REPORT_ZEROLEN',
        0x0002: 'IEEE80211_RADIOTAP_AMPDU_IS_ZEROLEN',
        0x0004: 'IEEE80211_RADIOTAP_AMPDU_LAST_KNOWN',
        0x0008: 'IEEE80211_RADIOTAP_AMPDU_IS_LAST',
        0x0010: 'IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_ERR',
        0x0020: 'IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_KNOWN',
        0x0040: 'IEEE80211_RADIOTAP_AMPDU_EOF',
        0x0080: 'IEEE80211_RADIOTAP_AMPDU_EOF_KNOWN',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(AMPDUFlags())  # type: ignore[arg-type]
