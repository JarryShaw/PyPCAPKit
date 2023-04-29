# -*- coding: utf-8 -*-
"""Protection Authority Bit Assignments
==========================================

.. module:: pcapkit.vendor.ipv4.protection_authority

This module contains the vendor crawler for **Protection Authority Bit Assignments**,
which is automatically generating :class:`pcapkit.const.ipv4.protection_authority.ProtectionAuthority`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ProtectionAuthority']

#: Protection authority registry.
DATA = {
    0: 'GENSER',
    1: 'SIOP-ESI',
    2: 'SCI',
    3: 'NSA',
    4: 'DOE',
    5: 'Unassigned',
    6: 'Unassigned',
    7: 'Field Termination Indicator',
}  # type: dict[int, str]


class ProtectionAuthority(Vendor):
    """Protection Authority Bit Assignments"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and value >= 0'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ipv4.protection_authority.DATA`).

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
        for code, name in data.items():
            renm = self.rename(name, code)  # type: ignore[arg-type]
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == '__main__':
    sys.exit(ProtectionAuthority())  # type: ignore[arg-type]
