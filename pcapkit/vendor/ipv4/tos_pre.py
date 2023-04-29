# -*- coding: utf-8 -*-
"""ToS (DS Field) Precedence
===============================

.. module:: pcapkit.vendor.ipv4.tos_pre

This module contains the vendor crawler for **ToS (DS Field) Precedence**,
which is automatically generating :class:`pcapkit.const.ipv4.tos_pre.ToSPrecedence`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ToSPrecedence']

#: ToS registry.
DATA = {
    0b111: 'Network Control',
    0b110: 'Internetwork Control',
    0b101: 'CRITIC/ECP',
    0b100: 'Flash Override',
    0b011: 'Flash',
    0b010: 'Immediate',
    0b001: 'Priority',
    0b000: 'Routine',
}  # type: dict[int, str]


class ToSPrecedence(Vendor):
    """ToS (DS Field) Precedence"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b000 <= value <= 0b111'

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
    sys.exit(ToSPrecedence())  # type: ignore[arg-type]
