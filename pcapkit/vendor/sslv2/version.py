# -*- coding: utf-8 -*-
"""SSLv2 Protocol Version
============================

.. module:: pcapkit.vendor.sslv2.version

This module contains the vendor crawler for **SSLv2 Protocol Version**, which
is automatically generating :class:`pcapkit.const.sslv2.version.Version`.

Any other version resolves to an unregistered member rather than raising, as an
SSLv3-capable client sends an SSLv2-framed ``CLIENT-HELLO`` reading ``0x0300``
(:rfc:`6101#appendix-E`).

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['Version']

###############################################################################
# NOTE: reads the hand-maintained :data:`~pcapkit.vendor.sslv2.version.DATA`, as
# draft-hickman-netscape-ssl-00 is no live registry.
###############################################################################

#: SSLv2 protocol version registry, transcribed from
#: draft-hickman-netscape-ssl-00 for the single value the draft defines.
#:
#: Maps the version value to the enumeration name it takes and the
#: ``SSL-*`` constant the comment above it renders. Names go through
#: :meth:`~Vendor.rename`, so the generated member is the
#: :meth:`~Vendor.safe_name` of the first element.
DATA = {
    2: ('SSLv2', '``SSL-2.0``'),
}  # type: dict[int, tuple[str, str]]


class Version(Vendor):
    """SSLv2 Protocol Version"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.sslv2.version.DATA`).

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
    sys.exit(Version())  # type: ignore[arg-type]
