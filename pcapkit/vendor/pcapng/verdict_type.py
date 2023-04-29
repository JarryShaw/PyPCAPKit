# -*- coding: utf-8 -*-
"""Verdict Types
===================

.. module:: pcapkit.vendor.pcapng.verdict_type

This module contains the vendor crawler for **Verdict Types**,
which is automatically generating :class:`pcapkit.const.pcapng.verdict_type.VerdictType`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['VerdictType']

#: Verdict type registry.
DATA = {
    0: 'Hardware',
    1: 'Linux_eBPF_TC',
    2: 'Linux_eBPF_XDP',
}  # type: dict[int, str]


class VerdictType(Vendor):
    """Verdict Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xFF'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.pcapng.verdict_type.DATA`).

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
    sys.exit(VerdictType())  # type: ignore[arg-type]
