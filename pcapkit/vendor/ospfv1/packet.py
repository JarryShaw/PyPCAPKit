# -*- coding: utf-8 -*-
"""OSPFv1 Packet Types
=========================

.. module:: pcapkit.vendor.ospfv1.packet

This module contains the vendor crawler for **OSPFv1 Packet Types**,
which is automatically generating :class:`pcapkit.const.ospfv1.packet.Packet`.

:rfc:`1131` Section A.2 defines types 1 to 5 alone; the IANA registry
:class:`~pcapkit.const.ospf.packet.Packet` is OSPFv2's.

.. versionadded:: 1.8.1

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['Packet']

###############################################################################
# NOTE: this crawler does not crawl: RFC 1131 is published as PostScript alone,
# so it reads the hand-maintained :data:`~pcapkit.vendor.ospfv1.packet.DATA`.
###############################################################################

#: OSPFv1 packet type registry, transcribed from :rfc:`1131` Section A.2.
#:
#: Maps a packet type to the enumeration name it takes and the comment above it.
#: Names go through :meth:`~Vendor.rename`, so the generated member is the
#: :meth:`~Vendor.safe_name` of the first element.
DATA = {
    1: ('Hello', 'Hello [:rfc:`1131`]'),
    2: ('Database Description', 'Database Description [:rfc:`1131`]'),
    3: ('Link State Request', 'Link State Request [:rfc:`1131`]'),
    4: ('Link State Update', 'Link State Update [:rfc:`1131`]'),
    5: ('Link State Ack', 'Link State Ack [:rfc:`1131`]'),
}  # type: dict[int, tuple[str, str]]


class Packet(Vendor):
    """OSPFv1 Packet Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ospfv1.packet.DATA`).

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
            pval = str(code)
            renm = self.rename(name, pval)

            enum.append(f'#: {self.wrap_comment(desc)}\n    {renm} = {pval}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(Packet())  # type: ignore[arg-type]
