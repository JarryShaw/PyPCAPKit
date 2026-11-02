# -*- coding: utf-8 -*-
"""Radiotap U-SIG Common Known Flags
=======================================

.. module:: pcapkit.vendor.radiotap.usig_common_known

This module contains the vendor crawler for **Radiotap U-SIG Common Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.usig_common_known.USIGCommonKnown`.

The registry is the bits of the U-SIG field's ``common`` besides its value subfields, as radiotap.org
tables them; see :mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a
member, and where its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['USIGCommonKnown']


class USIGCommonKnown(Flags):
    """Radiotap U-SIG Common Known Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFFFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/U-SIG.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'common'
    #: Masks of the value subfields, which the schema splits off.
    VALUES = (0x00007000, 0x00038000, 0x00040000, 0x01F80000, 0xFE000000,)  # type: tuple[int, ...]
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x00000001: 'IEEE80211_RADIOTAP_EHT_USIG_COMMON_PHY_VER_KNOWN',
        0x00000002: 'IEEE80211_RADIOTAP_EHT_USIG_COMMON_BW_KNOWN',
        0x00000004: 'IEEE80211_RADIOTAP_EHT_USIG_COMMON_UL_DL_KNOWN',
        0x00000008: 'IEEE80211_RADIOTAP_EHT_USIG_COMMON_BSS_COLOR_KNOWN',
        0x00000010: 'IEEE80211_RADIOTAP_EHT_USIG_COMMON_TXOP_KNOWN',
        0x00000020: 'IEEE80211_RADIOTAP_EHT_USIG_COMMON_BAD_USIG_CRC',
        0x00000040: 'IEEE80211_RADIOTAP_EHT_USIG_COMMON_VALIDATE_BITS_CHECKED',
        0x00000080: 'IEEE80211_RADIOTAP_EHT_USIG_COMMON_VALIDATE_BITS_OK',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(USIGCommonKnown())  # type: ignore[arg-type]
