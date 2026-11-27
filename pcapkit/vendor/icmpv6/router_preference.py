# -*- coding: utf-8 -*-
"""Router Selection Preferences
==================================

.. module:: pcapkit.vendor.icmpv6.router_preference

This module contains the vendor crawler for **Router Selection Preferences**,
which is automatically generating
:class:`pcapkit.const.icmpv6.router_preference.RouterPreference`.

The two-bit Prf of a Router Advertisement and of a Route Information option
(:rfc:`4191#section-2.1`) has no IANA registry, so :data:`DATA` transcribes the
RFC's table.

.. versionadded:: 1.9.0

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['RouterPreference']

#: Preference values, as :rfc:`4191#section-2.1` encodes them.
DATA = {
    0: 'Medium',
    1: 'High',
    2: 'Reserved',
    3: 'Low',
}  # type: dict[int, str]


class RouterPreference(Vendor):
    """Router Selection Preferences [:rfc:`4191`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 3'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.icmpv6.router_preference.DATA`).

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
            enum.append(f'#: {name} [:rfc:`4191#section-2.1`]\n    {renm} = {code}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(RouterPreference())  # type: ignore[arg-type]
