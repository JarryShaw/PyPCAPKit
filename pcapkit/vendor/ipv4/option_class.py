# -*- coding: utf-8 -*-
"""Option Classes
====================

.. module:: pcapkit.vendor.ipv4.option_class

This module contains the vendor crawler for **Option Classes**,
which is automatically generating :class:`pcapkit.const.ipv4.option_class.OptionClass`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['OptionClass']

#: Option class registry.
DATA = {
    0: 'control',
    1: 'reserved for future use',
    2: 'debugging and measurement',
    3: 'reserved for future use',
}  # type: dict[int, str]


class OptionClass(Vendor):
    """Option Classes"""

    #: Value limit checker.s
    FLAG = 'isinstance(value, int) and 0 <= value <= 3'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ipv4.option_class.DATA`).

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
    sys.exit(OptionClass())  # type: ignore[arg-type]
