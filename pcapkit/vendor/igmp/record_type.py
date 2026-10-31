# -*- coding: utf-8 -*-
"""IGMP Group Record Types
=============================

.. module:: pcapkit.vendor.igmp.record_type

This module contains the vendor crawler for **IGMP Group Record Types**,
which is automatically generating
:class:`pcapkit.const.igmp.record_type.RecordType`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['RecordType']

#: IGMPv3 group record type registry, per :rfc:`3376#section-4.2.12`. Unlike
#: :class:`~pcapkit.vendor.igmp.type.Type`, this is not an IANA-maintained
#: registry -- the six values are fixed in the RFC text itself -- so this
#: crawler returns the table directly rather than fetching a :attr:`LINK`,
#: following :class:`pcapkit.vendor.ipv4.qs_function.QSFunction`'s precedent
#: for an RFC-fixed, non-IANA enumeration.
DATA = {
    1: 'MODE_IS_INCLUDE',
    2: 'MODE_IS_EXCLUDE',
    3: 'CHANGE_TO_INCLUDE_MODE',
    4: 'CHANGE_TO_EXCLUDE_MODE',
    5: 'ALLOW_NEW_SOURCES',
    6: 'BLOCK_OLD_SOURCES',
}  # type: dict[int, str]


class RecordType(Vendor):
    """IGMP Group Record Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.igmp.record_type.DATA`).

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
            "return cls._unregistered_member(value, 'Unassigned')",
        ]
        for code, name in data.items():
            renm = self.rename(name, code)  # type: ignore[arg-type]
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == '__main__':
    sys.exit(RecordType())  # type: ignore[arg-type]
