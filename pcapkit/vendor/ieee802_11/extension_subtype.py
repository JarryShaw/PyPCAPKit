# -*- coding: utf-8 -*-
"""IEEE 802.11 Extension Frame Subtypes
==========================================

.. module:: pcapkit.vendor.ieee802_11.extension_subtype

This module contains the vendor crawler for **IEEE 802.11 Extension Frame Subtypes**,
which is automatically generating :class:`pcapkit.const.ieee802_11.extension_subtype.ExtensionSubtype`.

The crawler reads :data:`DATA` rather than a URL, for the reason
:mod:`pcapkit.vendor.ieee802_11` gives.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ExtensionSubtype']

#: Extension frame (Type ``0b11``) Subtype values (IEEE Std 802.11-2020,
#: Table 9-1).
#:
#: Maps a Subtype value to its *Subtype description*.
DATA = {
    0b0000: 'DMG Beacon',
    0b0001: 'S1G Beacon',
}  # type: dict[int, str]

#: Subtype ranges that Table 9-1 marks ``Reserved`` in one row, resolved by
#: ``_missing_`` under that bare label.
RESERVED = ((0b0010, 0b1111),)  # type: tuple[tuple[int, int], ...]


class ExtensionSubtype(Vendor):
    """IEEE 802.11 Extension Frame Subtypes [IEEE Std 802.11-2020, Table 9-1]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b0000 <= value <= 0b1111'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data
            (:data:`~pcapkit.vendor.ieee802_11.extension_subtype.DATA`).

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

        for start, stop in RESERVED:
            miss.append(f'if {start} <= value <= {stop}:')
            miss.append('    #: Reserved')
            miss.append("    return cls._unregistered_member(value, 'Reserved')")
        return enum, miss


if __name__ == '__main__':
    sys.exit(ExtensionSubtype())  # type: ignore[arg-type]
