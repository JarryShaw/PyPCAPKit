# -*- coding: utf-8 -*-
"""Link-Layer Address (LLA) Option Code
==========================================

.. module:: pcapkit.vendor.mh.lla_code

This module contains the vendor crawler for **Link-Layer Address (LLA) Option Code**,
which is automatically generating :class:`pcapkit.const.mh.lla_code.LLACode`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['LLACode']

#: LLA option codes.
DATA = {
    #: Wildcard requesting resolution for all nearby access points.
    0: 'Wilcard',
    #: Link-Layer Address of the New Access Point.
    1: 'New Access Point',
    #: Link-Layer Address of the MN.
    2: 'MH',
    #: Link-Layer Address of the NAR (i.e., Proxied Originator).
    3: 'NAR',
    #: Link-Layer Address of the source of RtSolPr or PrRtAdv.
    #: message.
    4: 'RtSolPr or PrRtAdv',
    #: The access point identified by the LLA belongs to the
    #: current interface of the router.
    5: 'access point',
    #: No prefix information available for the access point
    #: identified by the LLA.
    6: 'no prefix information',
    #: No fast handover support available for the access point
    #: identified by the LLA.
    7: 'no fast handover support',
}  # type: dict[int, str]



class LLACode(Vendor):
    """Link-Layer Address (LLA) Option Code"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ipv4.qs_function.DATA`).

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
    sys.exit(LLACode())  # type: ignore[arg-type]
