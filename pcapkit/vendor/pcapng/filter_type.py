# -*- coding: utf-8 -*-
"""Filter Types
==================

.. module:: pcapkit.vendor.pcapng.filter_type

This module contains the vendor crawler for **Filter Types**,
which is automatically generating :class:`pcapkit.const.pcapng.filter_type.FilterType`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['FilterType']

#: Filter type registry.
DATA = {
    # TODO: https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#section-4.2-28.2.1
}  # type: dict[int, str]


class FilterType(Vendor):
    """Filter Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00<= value <= 0xFF'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.pcapng.filter_type.DATA`).

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
    sys.exit(FilterType())  # type: ignore[arg-type]
