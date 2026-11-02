# -*- coding: utf-8 -*-
"""Radiotap VHT Coding Flags
===============================

.. module:: pcapkit.vendor.radiotap.vht_coding

This module contains the vendor crawler for **Radiotap VHT Coding Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.vht_coding.VHTCoding`.

The registry is the bits of the VHT field's ``coding``, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['VHTCoding']


class VHTCoding(Flags):
    """Radiotap VHT Coding Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/VHT.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'coding'
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x01: 'IEEE80211_RADIOTAP_CODING_LDPC_USER0',
        0x02: 'IEEE80211_RADIOTAP_CODING_LDPC_USER1',
        0x04: 'IEEE80211_RADIOTAP_CODING_LDPC_USER2',
        0x08: 'IEEE80211_RADIOTAP_CODING_LDPC_USER3',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(VHTCoding())  # type: ignore[arg-type]
