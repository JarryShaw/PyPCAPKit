# -*- coding: utf-8 -*-
"""IEEE 802.11 Management Frame Subtypes
===========================================

.. module:: pcapkit.vendor.ieee802_11.management_subtype

This module contains the vendor crawler for **IEEE 802.11 Management Frame Subtypes**,
which is automatically generating :class:`pcapkit.const.ieee802_11.management_subtype.ManagementSubtype`.

The crawler reads :data:`DATA` rather than a URL, for the reason
:mod:`pcapkit.vendor.ieee802_11` gives. Table 9-1 gives every value a row of
its own, so ``_missing_`` has no range to resolve.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ManagementSubtype']

#: Management frame (Type ``0b00``) Subtype values (IEEE Std 802.11-2020,
#: Table 9-1).
#:
#: Maps a Subtype value to its *Subtype description*. A single ``Reserved``
#: row is a member, which :meth:`~Vendor.rename` suffixes with its value.
DATA = {
    0b0000: 'Association Request',
    0b0001: 'Association Response',
    0b0010: 'Reassociation Request',
    0b0011: 'Reassociation Response',
    0b0100: 'Probe Request',
    0b0101: 'Probe Response',
    0b0110: 'Timing Advertisement',
    0b0111: 'Reserved',
    0b1000: 'Beacon',
    0b1001: 'ATIM',
    0b1010: 'Disassociation',
    0b1011: 'Authentication',
    0b1100: 'Deauthentication',
    0b1101: 'Action',
    0b1110: 'Action No Ack (NACK)',
    0b1111: 'Reserved',
}  # type: dict[int, str]


class ManagementSubtype(Vendor):
    """IEEE 802.11 Management Frame Subtypes [IEEE Std 802.11-2020, Table 9-1]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b0000 <= value <= 0b1111'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data
            (:data:`~pcapkit.vendor.ieee802_11.management_subtype.DATA`).

        """
        return DATA

    def count(self, data: 'dict[int, str]') -> 'Counter[str]':  # type: ignore[override]
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter(self.safe_name(name) for name in data.values())

    def process(self, data: 'dict[int, str]') -> 'tuple[list[str], list[str]]':  # type: ignore[override]
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = []  # type: list[str]

        for code, name in data.items():
            pval = str(code)
            renm = self.rename(name, pval)

            enum.append(f'#: {self.wrap_comment(name)}\n    {renm} = {pval}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(ManagementSubtype())  # type: ignore[arg-type]
