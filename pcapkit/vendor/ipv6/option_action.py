# -*- coding: utf-8 -*-
"""Option Actions
====================

.. module:: pcapkit.vendor.ipv6.option_action

This module contains the vendor crawler for **Option Actions**,
which is automatically generating :class:`pcapkit.const.ipv6.option_action.OptionAction`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['OptionAction']

#: Unknown option action [:rfc:`8200#section-4.2`].
DATA = {
    # skip over this option and continue processing the header.
    0b00: 'skip',
    # discard the packet.
    0b01: 'discard',
    # discard the packet and, regardless of whether or not the
    # packet's Destination Address was a multicast address, send an
    # ICMP Parameter Problem, Code 2, message to the packet's
    # Source Address, pointing to the unrecognized Option Type.
    0b10: 'discard_icmp_any',
    # discard the packet and, only if the packet's Destination
    # Address was not a multicast address, send an ICMP Parameter
    # Problem, Code 2, message to the packet's Source Address,
    # pointing to the unrecognized Option Type.
    0b11: 'discard_icmp_unicast',
}  # type: dict[int, str]


class OptionAction(Vendor):
    """Option Actions"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 3'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ipv6.option_action.DATA`).

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
    sys.exit(OptionAction())  # type: ignore[arg-type]
