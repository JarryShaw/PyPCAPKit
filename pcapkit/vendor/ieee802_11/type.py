# -*- coding: utf-8 -*-
"""IEEE 802.11 Frame Types
=============================

.. module:: pcapkit.vendor.ieee802_11.type

This module contains the vendor crawler for **IEEE 802.11 Frame Types**,
which is automatically generating :class:`pcapkit.const.ieee802_11.type.Type`.

The crawler reads :data:`DATA` rather than a URL, for the reason
:mod:`pcapkit.vendor.ieee802_11` gives. Table 9-1 names every value the
two-bit Type subfield can take, so no value in range is left for
``_missing_`` to resolve.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['Type']

#: IEEE 802.11 Type subfield values (IEEE Std 802.11-2020, Table 9-1).
#:
#: Maps a Type value to its *Type description*. Names go through
#: :meth:`~Vendor.rename`, so the generated member is the
#: :meth:`~Vendor.safe_name` of the description.
DATA = {
    0b00: 'Management',
    0b01: 'Control',
    0b10: 'Data',
    0b11: 'Extension',
}  # type: dict[int, str]


class Type(Vendor):
    """IEEE 802.11 Frame Types [IEEE Std 802.11-2020, Table 9-1]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b00 <= value <= 0b11'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ieee802_11.type.DATA`).

        """
        return DATA

    def count(self, data: 'dict[int, str]') -> 'Counter[str]':  # type: ignore[override]
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter(self.safe_name(name) for name in data.values())

    def process(self, data: 'dict[int, str]') -> 'tuple[list[str], list[str]]':  # type: ignore[override]
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = []  # type: list[str]

        for code, name in data.items():
            pval = str(code)
            renm = self.rename(name, pval)

            enum.append(f'#: {self.wrap_comment(name)}\n    {renm} = {pval}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(Type())  # type: ignore[arg-type]
