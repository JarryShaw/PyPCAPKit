# -*- coding: utf-8 -*-
"""Radiotap Channel Flags
============================

.. module:: pcapkit.vendor.radiotap.channel_flags

This module contains the vendor crawler for **Radiotap Channel Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.channel_flags.ChannelFlags`.

The registry is the bits of the Channel field's ``flags``, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['ChannelFlags']


class ChannelFlags(Flags):
    """Radiotap Channel Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/Channel.html'
    #: Subfield whose table is scraped.
    SUBFIELD = None
    #: The source macro of each bit, keyed by mask, which is Linux's, and
    #: Wireshark's ``packet-ieee80211-radiotap-defs.h`` for ``0x0010``,
    #: ``0x0200`` and ``0x0800``, which Linux leaves unnamed.
    NAMES = {
        0x0001: 'IEEE80211_CHAN_700MHZ',
        0x0002: 'IEEE80211_CHAN_800MHZ',
        0x0004: 'IEEE80211_CHAN_900MHZ',
        0x0010: 'IEEE80211_CHAN_TURBO',
        0x0020: 'IEEE80211_CHAN_CCK',
        0x0040: 'IEEE80211_CHAN_OFDM',
        0x0080: 'IEEE80211_CHAN_2GHZ',
        0x0100: 'IEEE80211_CHAN_5GHZ',
        0x0200: 'IEEE80211_CHAN_PASSIVE',
        0x0400: 'IEEE80211_CHAN_DYN',
        0x0800: 'IEEE80211_CHAN_GFSK',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(ChannelFlags())  # type: ignore[arg-type]
