# -*- coding: utf-8 -*-
"""BOOTP Message Op Codes
============================

.. module:: pcapkit.vendor.dhcp.opcode

This module contains the vendor crawler for **BOOTP Message Op Codes**,
which is automatically generating :class:`pcapkit.const.dhcp.opcode.Opcode`.

The crawler reads :data:`DATA` rather than a URL: the ``op`` field's two codes
are fixed by the text of :rfc:`951#section-3`, which :rfc:`2131#section-2`
keeps, and IANA publishes no registry for them.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['Opcode']

#: Message op codes of :rfc:`951#section-3`.
#:
#: Maps a code to the enumeration name it takes and the comment rendered
#: above it.
DATA = {
    1: ('BOOTREQUEST', 'BOOTREQUEST [:rfc:`951`]'),
    2: ('BOOTREPLY', 'BOOTREPLY [:rfc:`951`]'),
}  # type: dict[int, tuple[str, str]]


class Opcode(Vendor):
    """BOOTP Message Op Codes [:rfc:`951`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data
            (:data:`~pcapkit.vendor.dhcp.opcode.DATA`).

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
            renm = self.rename(name, str(code))
            enum.append(f'#: {self.wrap_comment(desc)}\n    {renm} = {code}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(Opcode())  # type: ignore[arg-type]
