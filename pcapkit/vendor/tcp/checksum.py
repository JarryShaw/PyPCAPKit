# -*- coding: utf-8 -*-
"""TCP Checksum
==================

.. module:: pcapkit.vendor.tcp.checksum

This module contains the vendor crawler for **TCP Checksum**,
which is automatically generating :class:`pcapkit.const.tcp.checksum.Checksum`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['Checksum']

#: TCP checksum options.
DATA = {
    0:  'TCP checksum',
    1:  "8-bit Fletcher's algorithm",
    2:  "16-bit Fletcher's algorithm",
    3:  'Redundant Checksum Avoidance',
}  # type: dict[int, str]


class Checksum(Vendor):
    """TCP Checksum [:rfc:`1146`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            TCP checksum options, i.e. :data:`~pcapkit.vendor.tcp.checksum.DATA`.

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
        """Process CSV data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = [
            "return extend_enum(cls, 'Unassigned_%d' % value, value)",
        ]
        for code, name in data.items():
            renm = self.rename(name, code)  # type: ignore[arg-type]
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == '__main__':
    sys.exit(Checksum())  # type: ignore[arg-type]
