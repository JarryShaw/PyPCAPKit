# -*- coding: utf-8 -*-
"""Radiotap HE-MU Flags1 Known Flags
=======================================

.. module:: pcapkit.vendor.radiotap.he_mu_flags1_known

This module contains the vendor crawler for **Radiotap HE-MU Flags1 Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.he_mu_flags1_known.HEMUFlags1Known`.

The registry is the bits of the HE-MU field's ``flags1`` besides its value subfields, as radiotap.org
tables them; see :mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a
member, and where its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['HEMUFlags1Known']


class HEMUFlags1Known(Flags):
    """Radiotap HE-MU Flags1 Known Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/HE-MU.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'flags1'
    #: Masks of the value subfields, which the schema splits off.
    VALUES = (0x000F, 0x0020, 0x2000,)  # type: tuple[int, ...]
    #: The source macro of each bit, keyed by mask, which is Linux's.
    NAMES = {
        0x0010: 'IEEE80211_RADIOTAP_HE_MU_FLAGS1_SIG_B_MCS_KNOWN',
        0x0040: 'IEEE80211_RADIOTAP_HE_MU_FLAGS1_SIG_B_DCM_KNOWN',
        0x0080: 'IEEE80211_RADIOTAP_HE_MU_FLAGS1_CH2_CTR_26T_RU_KNOWN',
        0x0100: 'IEEE80211_RADIOTAP_HE_MU_FLAGS1_CH1_RU_KNOWN',
        0x0200: 'IEEE80211_RADIOTAP_HE_MU_FLAGS1_CH2_RU_KNOWN',
        0x1000: 'IEEE80211_RADIOTAP_HE_MU_FLAGS1_CH1_CTR_26T_RU_KNOWN',
        0x4000: 'IEEE80211_RADIOTAP_HE_MU_FLAGS1_SIG_B_COMP_KNOWN',
        0x8000: 'IEEE80211_RADIOTAP_HE_MU_FLAGS1_SIG_B_SYMS_USERS_KNOWN',
    }  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(HEMUFlags1Known())  # type: ignore[arg-type]
