# -*- coding: utf-8 -*-
"""Radiotap HE-MU Flags2 Known Flags
=======================================

.. module:: pcapkit.vendor.radiotap.he_mu_flags2_known

This module contains the vendor crawler for **Radiotap HE-MU Flags2 Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.he_mu_flags2_known.HEMUFlags2Known`.

The registry is the bits of the HE-MU field's ``flags2`` besides its value subfields, as radiotap.org
tables them; see :mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a
member, and where its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['HEMUFlags2Known']


class HEMUFlags2Known(Flags):
    """Radiotap HE-MU Flags2 Known Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/HE-MU.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'flags2'
    #: Masks of the value subfields, which the schema splits off.
    VALUES = (0x0003, 0x0008, 0x00F0, 0x0300, 0x0800,)  # type: tuple[int, ...]
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x0004: 'IEEE80211_RADIOTAP_HE_MU_FLAGS2_BW_FROM_SIG_A_BW_KNOWN',
        0x0400: 'IEEE80211_RADIOTAP_HE_MU_FLAGS2_PUNC_FROM_SIG_A_BW_KNOWN',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(HEMUFlags2Known())  # type: ignore[arg-type]
