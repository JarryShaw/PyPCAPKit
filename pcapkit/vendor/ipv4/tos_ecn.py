# -*- coding: utf-8 -*-
"""ToS ECN Field
===================

.. module:: pcapkit.vendor.ipv4.tos_ecn

This module contains the vendor crawler for **ToS ECN Field**,
which is automatically generating :class:`pcapkit.const.ipv4.tos_ecn.ToSECN`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ToSECN']

#: ToS registry.
DATA = {
    0b00: 'Not-ECT',
    0b01: 'ECT(1)',
    0b10: 'ECT(0)',
    0b11: 'CE',
}  # type: dict[int, str]


class ToSECN(Vendor):
    """ToS ECN Field"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b00 <= value <= 0b11'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ipv4.tos_ecn.DATA`).

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

    def rename(self, name: 'str', code: 'int') -> 'str':  # type: ignore[override] # pylint: disable=arguments-differ
        """Rename duplicated fields.

        Args:
            name: Field name.
            code: Field code.

        Returns:
            Revised field name.

        """
        if self.record[self.safe_name(name)] > 1 or self.safe_name(name).upper() in ['UNASSIGNED', 'RESERVED']:
            name = f'{name} [0b{bin(code)[2:].zfill(2)}]'
        return self.safe_name(name)

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
        for code, name in DATA.items():
            renm = self.rename(name, code)
            enum.append(f"{renm} = 0b{bin(code)[2:].zfill(2)}".ljust(76))
        return enum, miss


if __name__ == '__main__':
    sys.exit(ToSECN())  # type: ignore[arg-type]
