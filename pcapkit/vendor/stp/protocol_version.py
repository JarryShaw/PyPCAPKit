# -*- coding: utf-8 -*-
"""STP Protocol Version Identifiers
======================================

.. module:: pcapkit.vendor.stp.protocol_version

This module contains the vendor crawler for **STP Protocol Version Identifiers**,
which is automatically generating :class:`pcapkit.const.stp.protocol_version.ProtocolVersion`.

The crawler reads :data:`DATA` rather than a URL, for the reason
:mod:`pcapkit.vendor.stp` gives. A value is the third octet of a BPDU, its
Protocol Version Identifier. No BPDU format takes version 1. Version 4 is the
SPT BPDU of Shortest Path Bridging, which extends the MST BPDU and which
:mod:`pcapkit` does not dissect.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ProtocolVersion']

#: Protocol Version Identifiers of :ieee:`802.1D-2004` clause 9 and
#: :ieee:`802.1Q-2022` clause 14.
#:
#: Maps a version to the enumeration name it takes and the comment rendered
#: above it.
DATA = {
    0x00: ('STP', 'Spanning Tree Protocol: Configuration and TCN BPDUs [:ieee:`802.1D-2004`]'),
    0x02: ('RSTP', 'Rapid Spanning Tree Protocol: RST BPDUs [:ieee:`802.1D-2004`]'),
    0x03: ('MSTP', 'Multiple Spanning Tree Protocol: MST BPDUs [:ieee:`802.1Q-2022`]'),
    0x04: ('SPT', 'Shortest Path Tree: SPT BPDUs [:ieee:`802.1Q-2022`]'),
}  # type: dict[int, tuple[str, str]]


class ProtocolVersion(Vendor):
    """STP Protocol Version Identifiers [:ieee:`802.1D-2004`; :ieee:`802.1Q-2022`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xFF'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data
            (:data:`~pcapkit.vendor.stp.protocol_version.DATA`).

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
    sys.exit(ProtocolVersion())  # type: ignore[arg-type]
