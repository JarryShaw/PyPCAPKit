# -*- coding: utf-8 -*-
"""Hash Algorithms
=====================

.. module:: pcapkit.vendor.pcapng.hash_algorithm

This module contains the vendor crawler for **Hash Algorithms**,
which is automatically generating :class:`pcapkit.const.pcapng.hash_algorithm.HashAlgorithm`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['HashAlgorithm']

#: Hash algorithm registry.
DATA = {
    0: "two's complement",
    1: 'XOR',
    2: 'CRC32',
    3: 'MD-5',
    4: 'SHA-1',
    5: 'Toeplitz',
}  # type: dict[int, str]


class HashAlgorithm(Vendor):
    """Hash Algorithms"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xFF'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.pcapng.hash_algorithm.DATA`).

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
    sys.exit(HashAlgorithm())  # type: ignore[arg-type]
