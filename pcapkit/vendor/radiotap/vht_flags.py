# -*- coding: utf-8 -*-
"""Radiotap VHT Flags
========================

.. module:: pcapkit.vendor.radiotap.vht_flags

This module contains the vendor crawler for **Radiotap VHT Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.vht_flags.VHTFlags`.

The registry is the bits of the VHT field's ``flags``, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['VHTFlags']


class VHTFlags(Flags):
    """Radiotap VHT Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/VHT.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'flags'
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x01: 'IEEE80211_RADIOTAP_VHT_FLAG_STBC',
        0x02: 'IEEE80211_RADIOTAP_VHT_FLAG_TXOP_PS_NA',
        0x04: 'IEEE80211_RADIOTAP_VHT_FLAG_SGI',
        0x08: 'IEEE80211_RADIOTAP_VHT_FLAG_SGI_NSYM_M10_9',
        0x10: 'IEEE80211_RADIOTAP_VHT_FLAG_LDPC_EXTRA_OFDM_SYM',
        0x20: 'IEEE80211_RADIOTAP_VHT_FLAG_BEAMFORMED',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(VHTFlags())  # type: ignore[arg-type]
