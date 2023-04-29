# -*- coding: utf-8 -*-
"""L2TP Type
===============

.. module:: pcapkit.vendor.l2tp.type

This module contains the vendor crawler for **L2TP Type**,
which is automatically generating :class:`pcapkit.const.l2tp.type.Type`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['Type']

#: L2TP packet types.
DATA = {
    0:  'Control',
    1:  'Data',
}  # type: dict[int, str]


class Type(Vendor):
    """L2TP Type"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 1'

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

    def process(self, data: 'dict[int, str]') -> 'tuple[list[str], list[str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Process CSV data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = list()
        miss = [
            "return extend_enum(cls, 'Unassigned_%d' % value, value)",
        ]
        for code, name in data.items():
            renm = self.rename(name, code)  # type: ignore[arg-type]
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == '__main__':
    sys.exit(Type())  # type: ignore[arg-type]
