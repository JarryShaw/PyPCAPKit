# -*- coding: utf-8 -*-
"""TS Flag
=============

.. module:: pcapkit.vendor.ipv4.ts_flag

This module contains the vendor crawler for **TS Flag**,
which is automatically generating :class:`pcapkit.const.ipv4.ts_flag.TSFlag`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['TSFlag']

#: TS flag registry [:rfc:`719#section-3.1`].
DATA = {
    0: 'Timestamp Only',
    1: 'IP with Timestamp',
    3: 'Prespecified IP with Timestamp',
}  # type: dict[int, str]


class TSFlag(Vendor):
    """TS Flag"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b0000 <= value <= 0b1111'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ipv4.tos_pre.DATA`).

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
            "return extend_enum(cls, 'Unassigned_%d' % value, value)",
        ]
        for code, name in DATA.items():
            renm = self.rename(name, code)  # type: ignore[arg-type]
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == '__main__':
    sys.exit(TSFlag())  # type: ignore[arg-type]
