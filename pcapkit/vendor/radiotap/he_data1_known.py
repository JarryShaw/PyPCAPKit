# -*- coding: utf-8 -*-
"""Radiotap HE Data1 Known Flags
===================================

.. module:: pcapkit.vendor.radiotap.he_data1_known

This module contains the vendor crawler for **Radiotap HE Data1 Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.he_data1_known.HEData1Known`.

The registry is the bits of the HE field's ``data1`` besides its value subfields, as radiotap.org
tables them; see :mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a
member, and where its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['HEData1Known']


class HEData1Known(Flags):
    """Radiotap HE Data1 Known Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/HE.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'data1'
    #: Masks of the value subfields, which the schema splits off.
    VALUES = (0x0003,)  # type: tuple[int, ...]
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x0004: 'IEEE80211_RADIOTAP_HE_DATA1_BSS_COLOR_KNOWN',
        0x0008: 'IEEE80211_RADIOTAP_HE_DATA1_BEAM_CHANGE_KNOWN',
        0x0010: 'IEEE80211_RADIOTAP_HE_DATA1_UL_DL_KNOWN',
        0x0020: 'IEEE80211_RADIOTAP_HE_DATA1_DATA_MCS_KNOWN',
        0x0040: 'IEEE80211_RADIOTAP_HE_DATA1_DATA_DCM_KNOWN',
        0x0080: 'IEEE80211_RADIOTAP_HE_DATA1_CODING_KNOWN',
        0x0100: 'IEEE80211_RADIOTAP_HE_DATA1_LDPC_XSYMSEG_KNOWN',
        0x0200: 'IEEE80211_RADIOTAP_HE_DATA1_STBC_KNOWN',
        0x0400: 'IEEE80211_RADIOTAP_HE_DATA1_SPTL_REUSE_KNOWN',
        0x0800: 'IEEE80211_RADIOTAP_HE_DATA1_SPTL_REUSE2_KNOWN',
        0x1000: 'IEEE80211_RADIOTAP_HE_DATA1_SPTL_REUSE3_KNOWN',
        0x2000: 'IEEE80211_RADIOTAP_HE_DATA1_SPTL_REUSE4_KNOWN',
        0x4000: 'IEEE80211_RADIOTAP_HE_DATA1_BW_RU_ALLOC_KNOWN',
        0x8000: 'IEEE80211_RADIOTAP_HE_DATA1_DOPPLER_KNOWN',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(HEData1Known())  # type: ignore[arg-type]
