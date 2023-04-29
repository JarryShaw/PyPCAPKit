# -*- coding: utf-8 -*-
"""Seed-ID Types
===================

.. module:: pcapkit.vendor.ipv6.seed_id

This module contains the vendor crawler for **Seed-ID Types**,
which is automatically generating :class:`pcapkit.const.ipv6.seed_id.SeedID`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['SeedID']

#: Seed-ID type registry [:rfc:`7731`].
DATA = {
    0b00: 'IPv6 Source Address',                   # [RFC 7731]
    0b01: '16-Bit Unsigned Integer',               # [RFC 7731]
    0b10: '64-Bit Unsigned Integer',               # [RFC 7731]
    0b11: '128-Bit Unsigned Integer',              # [RFC 7731]
}  # type: dict[int, str]


class SeedID(Vendor):
    """Seed-ID Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b00 <= value <= 0b11'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:attr:`~pcapkit.vendor.ipv6.seed_id.DATA`).

        """
        return DATA

    def count(self, data: 'dict[int, str]') -> 'Counter[str]':  # type: ignore[override]
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter(map(self.safe_name, data.values()))

    def process(self, data: 'dict[int, str]') -> 'tuple[list[str], list[str]]':  # type: ignore[override]
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = [
            "return extend_enum(cls, 'Unassigned_0b%s' % bin(value)[2:].zfill(2), value)",
        ]
        for code, name in data.items():
            bncd = f'0b{bin(code)[2:].zfill(2)}'
            renm = self.rename(name, bncd).upper()
            enum.append(f"{renm} = {bncd}".ljust(76))
        return enum, miss


if __name__ == '__main__':
    sys.exit(SeedID())  # type: ignore[arg-type]
