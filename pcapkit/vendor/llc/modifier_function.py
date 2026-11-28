# -*- coding: utf-8 -*-
"""LLC Modifier Functions
============================

.. module:: pcapkit.vendor.llc.modifier_function

This module contains the vendor crawler for **LLC Modifier Functions**,
which is automatically generating :class:`pcapkit.const.llc.modifier_function.ModifierFunction`.

The crawler reads :data:`DATA` rather than a URL, for the reason
:mod:`pcapkit.vendor.llc` gives. A value is a U-format control field masked to
its modifier function bits, ``0xEC``, leaving out the format bits and the
P/F bit, as Wireshark's ``packet-xdlc.h`` spells the HDLC values LLC shares
with it. Whether a value is a command or a response is the SSAP's C/R bit;
no value is both one command and another response.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ModifierFunction']

#: U-format commands and responses of IEEE Std 802.2, of LLC types 1, 2
#: and 3.
#:
#: Maps a function value to the enumeration name it takes and the comment
#: rendered above it.
DATA = {
    0x00: ('UI', 'Unnumbered Information (command)'),
    0x0C: ('DM', 'Disconnected Mode (response)'),
    0x40: ('DISC', 'Disconnect (command)'),
    0x60: ('UA', 'Unnumbered Acknowledgment (response)'),
    0x64: ('AC0', 'Acknowledged Connectionless Information, sequence 0 (command and response)'),
    0x6C: ('SABME', 'Set Asynchronous Balanced Mode Extended (command)'),
    0x84: ('FRMR', 'Frame Reject (response)'),
    0xAC: ('XID', 'Exchange Identification (command and response)'),
    0xE0: ('TEST', 'Test (command and response)'),
    0xE4: ('AC1', 'Acknowledged Connectionless Information, sequence 1 (command and response)'),
}  # type: dict[int, tuple[str, str]]


class ModifierFunction(Vendor):
    """LLC Modifier Functions [IEEE Std 802.2]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xEC and not value & 0x13'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data
            (:data:`~pcapkit.vendor.llc.modifier_function.DATA`).

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
    sys.exit(ModifierFunction())  # type: ignore[arg-type]
