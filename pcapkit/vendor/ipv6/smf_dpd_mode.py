# -*- coding: utf-8 -*-
"""Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options
======================================================================================

.. module:: pcapkit.vendor.ipv6.smf_dpd_mode

This module contains the vendor crawler for **Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options**,
which is automatically generating :class:`pcapkit.const.ipv6.smf_dpd_mode.SMFDPDMode`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['SMFDPDMode']

#: ``SMF_DPD`` mode registry.
DATA = {
    0:  'I-DPD',
    1:  'H-DPD',
}  # type: dict[int, str]


class SMFDPDMode(Vendor):
    """Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 1'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ipv6.smf_dpd_mode.DATA`).

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
    sys.exit(SMFDPDMode())  # type: ignore[arg-type]
