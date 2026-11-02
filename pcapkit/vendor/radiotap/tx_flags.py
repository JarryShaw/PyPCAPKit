# -*- coding: utf-8 -*-
"""Radiotap TX Flags
=======================

.. module:: pcapkit.vendor.radiotap.tx_flags

This module contains the vendor crawler for **Radiotap TX Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.tx_flags.TXFlags`.

The registry is the bits of the TX flags field, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['TXFlags']


class TXFlags(Flags):
    """Radiotap TX Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/TX%20flags.html'
    #: Subfield whose table is scraped.
    SUBFIELD = None
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x0001: 'IEEE80211_RADIOTAP_F_TX_FAIL',
        0x0002: 'IEEE80211_RADIOTAP_F_TX_CTS',
        0x0004: 'IEEE80211_RADIOTAP_F_TX_RTS',
        0x0008: 'IEEE80211_RADIOTAP_F_TX_NOACK',
        0x0010: 'IEEE80211_RADIOTAP_F_TX_NOSEQNO',
        0x0020: 'IEEE80211_RADIOTAP_F_TX_ORDER',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(TXFlags())  # type: ignore[arg-type]
