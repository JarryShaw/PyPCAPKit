# -*- coding: utf-8 -*-
"""Radiotap HE-MU-other-user Known Flags
===========================================

.. module:: pcapkit.vendor.radiotap.he_mu_other_user_known

This module contains the vendor crawler for **Radiotap HE-MU-other-user Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.he_mu_other_user_known.HEMUOtherUserKnown`.

The registry is the bits of the HE-MU-other-user field's ``per_user_known``, as radiotap.org tables them; see
:mod:`pcapkit.vendor.radiotap.flags` for how a row becomes a member, and where
its name comes from.

"""

import sys

from pcapkit.vendor.radiotap.flags import Flags

__all__ = ['HEMUOtherUserKnown']


class HEMUOtherUserKnown(Flags):
    """Radiotap HE-MU-other-user Known Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/HE-MU-other-user.html'
    #: Subfield whose table is scraped.
    SUBFIELD = 'per_user_known'
    #: No bit has a source macro, since neither Linux nor Wireshark names these
    #: bits, so each member takes radiotap.org's wording.
    NAMES = {}  # type: dict[int, str]


if __name__ == '__main__':
    sys.exit(HEMUOtherUserKnown())  # type: ignore[arg-type]
