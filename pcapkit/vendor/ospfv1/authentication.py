# -*- coding: utf-8 -*-
"""OSPFv1 Authentication Types
=================================

.. module:: pcapkit.vendor.ospfv1.authentication

This module contains the vendor crawler for **OSPFv1 Authentication Types**,
which is automatically generating :class:`pcapkit.const.ospfv1.authentication.Authentication`.

:rfc:`1131` defines AuType 0 and 1 alone (Section A.2, Appendix E): it reserves 0 to
255 for its own definition and leaves those past 255 to each Autonomous System. The
IANA registry :class:`~pcapkit.const.ospf.authentication.Authentication` names later
OSPFv2 codes, which OSPFv1 does not define.

.. versionadded:: 1.8.1

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['Authentication']

###############################################################################
# NOTE: this crawler does not crawl: RFC 1131 is published as PostScript alone,
# so it reads the hand-maintained :data:`~pcapkit.vendor.ospfv1.authentication.DATA`.
###############################################################################

#: OSPFv1 authentication type registry, transcribed from :rfc:`1131` Appendix E.
#:
#: Maps an AuType to the enumeration name it takes and the comment above it.
#: Names go through :meth:`~Vendor.rename`, so the generated member is the
#: :meth:`~Vendor.safe_name` of the first element.
DATA = {
    0: ('No authentication', 'No authentication [:rfc:`1131`]'),
    1: ('Simple password', 'Simple password [:rfc:`1131`]'),
}  # type: dict[int, tuple[str, str]]

#: The ranges :rfc:`1131` Section A.2 leaves undefined, as ``(start, stop, label, comment)``.
RANGES = (
    (2, 255, 'Reserved', 'Reserved for definition by the specification [:rfc:`1131`]'),
    (256, 65535, 'Assigned per Autonomous System',
     'Assigned per Autonomous System [:rfc:`1131`]'),
)  # type: tuple[tuple[int, int, str, str], ...]


class Authentication(Vendor):
    """OSPFv1 Authentication Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ospfv1.authentication.DATA`).

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
        miss = []  # type: list[str]

        for code, (name, desc) in data.items():
            pval = str(code)
            renm = self.rename(name, pval)

            enum.append(f'#: {self.wrap_comment(desc)}\n    {renm} = {pval}')
        for start, stop, name, desc in RANGES:
            miss.append(f'if {start} <= value <= {stop}:')
            miss.append(f'    #: {desc}')
            miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(name)}')")
        return enum, miss


if __name__ == '__main__':
    sys.exit(Authentication())  # type: ignore[arg-type]
