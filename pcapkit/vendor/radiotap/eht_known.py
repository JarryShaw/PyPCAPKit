# -*- coding: utf-8 -*-
"""Radiotap EHT Known Flags
==============================

.. module:: pcapkit.vendor.radiotap.eht_known

This module contains the vendor crawler for **Radiotap EHT Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.eht_known.EHTKnown`.

The registry is the bits of the EHT field's ``known``, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['EHTKnown']


class EHTKnown(Flags):
    """Radiotap EHT Known Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFFFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/EHT.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'known'
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x00000002: 'IEEE80211_RADIOTAP_EHT_KNOWN_SPATIAL_REUSE',
        0x00000004: 'IEEE80211_RADIOTAP_EHT_KNOWN_GI',
        0x00000010: 'IEEE80211_RADIOTAP_EHT_KNOWN_EHT_LTF',
        0x00000020: 'IEEE80211_RADIOTAP_EHT_KNOWN_LDPC_EXTRA_SYM_OM',
        0x00000040: 'IEEE80211_RADIOTAP_EHT_KNOWN_PRE_PADD_FACOR_OM',
        0x00000080: 'IEEE80211_RADIOTAP_EHT_KNOWN_PE_DISAMBIGUITY_OM',
        0x00000100: 'IEEE80211_RADIOTAP_EHT_KNOWN_DISREGARD_O',
        0x00000200: 'IEEE80211_RADIOTAP_EHT_KNOWN_DISREGARD_S',
        0x00002000: 'IEEE80211_RADIOTAP_EHT_KNOWN_CRC1',
        0x00004000: 'IEEE80211_RADIOTAP_EHT_KNOWN_TAIL1',
        0x00008000: 'IEEE80211_RADIOTAP_EHT_KNOWN_CRC2_O',
        0x00010000: 'IEEE80211_RADIOTAP_EHT_KNOWN_TAIL2_O',
        0x00020000: 'IEEE80211_RADIOTAP_EHT_KNOWN_NSS_S',
        0x00040000: 'IEEE80211_RADIOTAP_EHT_KNOWN_BEAMFORMED_S',
        0x00080000: 'IEEE80211_RADIOTAP_EHT_KNOWN_NR_NON_OFDMA_USERS_M',
        0x00100000: 'IEEE80211_RADIOTAP_EHT_KNOWN_ENCODING_BLOCK_CRC_M',
        0x00200000: 'IEEE80211_RADIOTAP_EHT_KNOWN_ENCODING_BLOCK_TAIL_M',
        0x00400000: 'IEEE80211_RADIOTAP_EHT_KNOWN_RU_MRU_SIZE_OM',
        0x00800000: 'IEEE80211_RADIOTAP_EHT_KNOWN_RU_MRU_INDEX_OM',
        0x01000000: 'IEEE80211_RADIOTAP_EHT_KNOWN_RU_ALLOC_TB_FMT',
        0x02000000: 'IEEE80211_RADIOTAP_EHT_KNOWN_PRIMARY_80',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(EHTKnown())  # type: ignore[arg-type]
