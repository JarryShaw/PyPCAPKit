# -*- coding: utf-8 -*-
"""STP BPDU Types
====================

.. module:: pcapkit.vendor.stp.bpdu_type

This module contains the vendor crawler for **STP BPDU Types**,
which is automatically generating :class:`pcapkit.const.stp.bpdu_type.BPDUType`.

The crawler reads :data:`DATA` rather than a URL, for the reason
:mod:`pcapkit.vendor.stp` gives. A value is the fourth octet of a BPDU, its
BPDU Type. The RST, MST and SPT BPDUs share type ``0x02`` and are told apart
by the Protocol Version Identifier, as :ieee:`802.1Q-2022` clause 14.4
validates them.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['BPDUType']

#: BPDU Types of :ieee:`802.1D-2004` clause 9 and :ieee:`802.1Q-2022`
#: clause 14.
#:
#: Maps a type to the enumeration name it takes and the comment rendered
#: above it.
DATA = {
    0x00: ('Configuration', 'Configuration BPDU [:ieee:`802.1D-2004`]'),
    0x02: ('RST', 'RST BPDU, and the MST and SPT BPDUs [:ieee:`802.1D-2004`; :ieee:`802.1Q-2022`]'),
    0x80: ('TCN', 'Topology Change Notification BPDU [:ieee:`802.1D-2004`]'),
}  # type: dict[int, tuple[str, str]]


class BPDUType(Vendor):
    """STP BPDU Types [:ieee:`802.1D-2004`; :ieee:`802.1Q-2022`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xFF'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data
            (:data:`~pcapkit.vendor.stp.bpdu_type.DATA`).

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
    sys.exit(BPDUType())  # type: ignore[arg-type]
