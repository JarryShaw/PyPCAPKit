# -*- coding: utf-8 -*-
"""STP Port Roles
====================

.. module:: pcapkit.vendor.stp.port_role

This module contains the vendor crawler for **STP Port Roles**,
which is automatically generating :class:`pcapkit.const.stp.port_role.PortRole`.

The crawler reads :data:`DATA` rather than a URL, for the reason
:mod:`pcapkit.vendor.stp` gives. A value is the two-bit Port Role of the flags
of an RST or MST BPDU, or of an MSTI Configuration Message, bits 3 and 4 of
the octet. :ieee:`802.1Q-2022` encodes ``0`` as a Master Port, a role an MSTI
alone takes, so in the MSTI Flags it is Master; in the CIST Flags of an RST or
MST BPDU it is Unknown, as :ieee:`802.1D-2004` names it.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['PortRole']

#: Port Role encodings of :ieee:`802.1Q-2022` clause 14.
#:
#: Maps a role to the enumeration name it takes and the comment rendered
#: above it.
DATA = {
    0x00: ('Master', 'Master Port in the MSTI Flags; Unknown in the CIST Flags, as '
                     ':ieee:`802.1D-2004` names it [:ieee:`802.1Q-2022`]'),
    0x01: ('Alternate_or_Backup', 'Alternate or Backup Port [:ieee:`802.1Q-2022`]'),
    0x02: ('Root', 'Root Port [:ieee:`802.1Q-2022`]'),
    0x03: ('Designated', 'Designated Port [:ieee:`802.1Q-2022`]'),
}  # type: dict[int, tuple[str, str]]


class PortRole(Vendor):
    """STP Port Roles [:ieee:`802.1Q-2022`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0x03'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data
            (:data:`~pcapkit.vendor.stp.port_role.DATA`).

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
    sys.exit(PortRole())  # type: ignore[arg-type]
