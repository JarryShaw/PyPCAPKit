# -*- coding: utf-8 -*-
"""Radiotap VHT Known Flags
==============================

.. module:: pcapkit.vendor.radiotap.vht_known

This module contains the vendor crawler for **Radiotap VHT Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.vht_known.VHTKnown`.

The registry is the bits of the VHT field's ``known``, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['VHTKnown']


class VHTKnown(Flags):
    """Radiotap VHT Known Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/VHT.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'known'
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x0001: 'IEEE80211_RADIOTAP_VHT_KNOWN_STBC',
        0x0002: 'IEEE80211_RADIOTAP_VHT_KNOWN_TXOP_PS_NA',
        0x0004: 'IEEE80211_RADIOTAP_VHT_KNOWN_GI',
        0x0008: 'IEEE80211_RADIOTAP_VHT_KNOWN_SGI_NSYM_DIS',
        0x0010: 'IEEE80211_RADIOTAP_VHT_KNOWN_LDPC_EXTRA_OFDM_SYM',
        0x0020: 'IEEE80211_RADIOTAP_VHT_KNOWN_BEAMFORMED',
        0x0040: 'IEEE80211_RADIOTAP_VHT_KNOWN_BANDWIDTH',
        0x0080: 'IEEE80211_RADIOTAP_VHT_KNOWN_GROUP_ID',
        0x0100: 'IEEE80211_RADIOTAP_VHT_KNOWN_PARTIAL_AID',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(VHTKnown())  # type: ignore[arg-type]
