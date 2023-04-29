# -*- coding: utf-8 -*-
"""ToS (DS Field) Delay
==========================

.. module:: pcapkit.vendor.ipv4.tos_del

This module contains the vendor crawler for **ToS (DS Field) Delay**,
which is automatically generating :class:`pcapkit.const.ipv4.tos_del.ToSDelay`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ToSDelay']

#: ToS registry.
DATA = {
    0: 'Normal',
    1: 'Low',
}  # type: dict[int, str]


class ToSDelay(Vendor):
    """ToS (DS Field) Delay"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 1'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ipv4.tos_del.DATA`).

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
            renm = self.rename(name, code).upper()  # type: ignore[arg-type]
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == '__main__':
    sys.exit(ToSDelay())  # type: ignore[arg-type]
