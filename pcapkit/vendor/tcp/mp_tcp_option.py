# -*- coding: utf-8 -*-
"""Multipath TCP options
===========================

This module contains the vendor crawler for **Multipath TCP options**,
which is automatically generating :class:`pcapkit.const.tcp.mp_tcp_option.MPTCPOption`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['MPTCPOption']

#: Multipath TCP options.
DATA = {   # [RFC 6824]
    0: 'MP_CAPABLE',
    1: 'MP_JOIN',
    2: 'DSS',
    3: 'ADD_ADDR',
    4: 'REMOVE_ADDR',
    5: 'MP_PRIO',
    6: 'MP_FAIL',
    7: 'MP_FASTCLOSE',
}  # type: dict[int, str]


class MPTCPOption(Vendor):
    """Multipath TCP options [:rfc:`6824`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Multipath TCP options, i.e. :data:`~pcapkit.vendor.tcp.mp_tcp_option.DATA`.

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
            "extend_enum(cls, 'Unassigned_%d' % value, value)",
            'return cls(value)'
        ]
        for code, name in data.items():
            renm = self.rename(name, code)  # type: ignore[arg-type]
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == '__main__':
    sys.exit(MPTCPOption())
