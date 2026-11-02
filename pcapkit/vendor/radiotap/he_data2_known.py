# -*- coding: utf-8 -*-
"""Radiotap HE Data2 Known Flags
===================================

.. module:: pcapkit.vendor.radiotap.he_data2_known

This module contains the vendor crawler for **Radiotap HE Data2 Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.he_data2_known.HEData2Known`.

The registry is the bits of the HE field's ``data2`` besides its value subfields, as radiotap.org
tables them; see :mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a
member, and where its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['HEData2Known']


class HEData2Known(Flags):
    """Radiotap HE Data2 Known Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/HE.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'data2'
    #: Masks of the value subfields, which the schema splits off.
    VALUES = (0x3F00, 0x8000,)  # type: tuple[int, ...]
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x0001: 'IEEE80211_RADIOTAP_HE_DATA2_PRISEC_80_KNOWN',
        0x0002: 'IEEE80211_RADIOTAP_HE_DATA2_GI_KNOWN',
        0x0004: 'IEEE80211_RADIOTAP_HE_DATA2_NUM_LTF_SYMS_KNOWN',
        0x0008: 'IEEE80211_RADIOTAP_HE_DATA2_PRE_FEC_PAD_KNOWN',
        0x0010: 'IEEE80211_RADIOTAP_HE_DATA2_TXBF_KNOWN',
        0x0020: 'IEEE80211_RADIOTAP_HE_DATA2_PE_DISAMBIG_KNOWN',
        0x0040: 'IEEE80211_RADIOTAP_HE_DATA2_TXOP_KNOWN',
        0x0080: 'IEEE80211_RADIOTAP_HE_DATA2_MIDAMBLE_KNOWN',
        0x4000: 'IEEE80211_RADIOTAP_HE_DATA2_RU_OFFSET_KNOWN',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(HEData2Known())  # type: ignore[arg-type]
