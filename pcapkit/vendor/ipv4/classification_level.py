# -*- coding: utf-8 -*-
"""Classification Level Encodings
====================================

.. module:: pcapkit.vendor.ipv4.classification_level

This module contains the vendor crawler for **Classification Level Encodings**,
which is automatically generating :class:`pcapkit.const.ipv4.classification_level.ClassificationLevel`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ClassificationLevel']

#: Encoding registry.
DATA = {
    0b0000_0001: 'Reserved [4]',
    0b0011_1101: 'Top Secret',
    0b0101_1010: 'Secret',
    0b1001_0110: 'Confidential',
    0b0110_0110: 'Reserved [3]',
    0b1100_1100: 'Reserved [2]',
    0b1010_1011: 'Unclassified',
    0b1111_0001: 'Reserved [1]',
}  # type: dict[int, str]


def binary(code: 'int') -> 'str':
    """Convert code to binary form."""
    return f'0b{bin(code)[2:].upper().zfill(8)}'


class ClassificationLevel(Vendor):
    """Classification Level Encodings"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b00000000 <= value <= 0b11111111'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ipv4.classification_level.DATA`).

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
            'temp = bin(value)[2:].upper().zfill(8)',
            "return extend_enum(cls, 'Unassigned_0b%s' % (temp[:4]+'_'+temp[4:]), value)",
        ]
        for code, name in data.items():
            bncd = binary(code)
            renm = self.rename(name, bncd)
            enum.append(f"{renm} = {bncd}".ljust(76))
        return enum, miss


if __name__ == '__main__':
    sys.exit(ClassificationLevel())  # type: ignore[arg-type]
