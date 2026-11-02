# -*- coding: utf-8 -*-
"""Radiotap RX Flags
=======================

.. module:: pcapkit.vendor.radiotap.rx_flags

This module contains the vendor crawler for **Radiotap RX Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.rx_flags.RXFlags`.

The registry is the bits of the RX flags field, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['RXFlags']


class RXFlags(Flags):
    """Radiotap RX Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/RX%20flags.html'
    #: Subfield whose table is scraped.
    SUBFIELD = None
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x0002: 'IEEE80211_RADIOTAP_F_RX_BADPLCP',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(RXFlags())  # type: ignore[arg-type]
