# -*- coding: utf-8 -*-
"""ToS (DS Field) Throughput
===============================

.. module:: pcapkit.vendor.ipv4.tos_thr

This module contains the vendor crawler for **ToS (DS Field) Throughput**,
which is automatically generating :class:`pcapkit.const.ipv4.tos_thr.ToSThroughput`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ToSThroughput']

#: ToS registry.
DATA = {
    0: 'Normal',
    1: 'High',
}  # type: dict[int, str]


class ToSThroughput(Vendor):
    """ToS (DS Field) Throughput"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 1'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ipv4.tos_thr.DATA`).

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
    sys.exit(ToSThroughput())  # type: ignore[arg-type]
