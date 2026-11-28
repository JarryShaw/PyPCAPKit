# -*- coding: utf-8 -*-
"""LLC Supervisory Functions
===============================

.. module:: pcapkit.vendor.llc.supervisory_function

This module contains the vendor crawler for **LLC Supervisory Functions**,
which is automatically generating :class:`pcapkit.const.llc.supervisory_function.SupervisoryFunction`.

The crawler reads :data:`DATA` rather than a URL, for the reason
:mod:`pcapkit.vendor.llc` gives. A value is the first octet of an S-format
control field masked to its supervisory function bits, ``0x0C``, as
Wireshark's ``packet-xdlc.h`` spells ``XDLC_RR``, ``XDLC_RNR`` and
``XDLC_REJ``. LLC defines no fourth function, so ``0x0C``, HDLC's selective
reject, is unassigned.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['SupervisoryFunction']

#: S-format commands and responses of IEEE Std 802.2.
#:
#: Maps a function value to the enumeration name it takes and the comment
#: rendered above it.
DATA = {
    0x00: ('RR', 'Receive Ready'),
    0x04: ('RNR', 'Receive Not Ready'),
    0x08: ('REJ', 'Reject'),
}  # type: dict[int, tuple[str, str]]


class SupervisoryFunction(Vendor):
    """LLC Supervisory Functions [IEEE Std 802.2]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0x0C and not value & 0x03'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data
            (:data:`~pcapkit.vendor.llc.supervisory_function.DATA`).

        """
        return DATA

    def count(self, data: 'dict[int, tuple[str, str]]') -> 'Counter[str]':  # type: ignore[override]
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter(self.safe_name(name) for name, _ in data.values())

    def process(self, data: 'dict[int, tuple[str, str]]') -> 'tuple[list[str], list[str]]':  # type: ignore[override]
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

        for code, (name, desc) in data.items():
            pval = f'0x{code:02X}'
            renm = self.rename(name, pval)

            enum.append(f'#: {self.wrap_comment(desc)}\n    {renm} = {pval}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(SupervisoryFunction())  # type: ignore[arg-type]
