# -*- coding: utf-8 -*-
"""Secrets Types
===================

.. module:: pcapkit.vendor.pcapng.secrets_type

This module contains the vendor crawler for **Secrets Types**,
which is automatically generating :class:`pcapkit.const.pcapng.secrets_type.SecretsType`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['SecretsType']

#: Secrets type registry.
DATA = {
    0x544c534b: 'TLS Key Log',     # NSS Key Log Format
    0x57474b4c: 'WireGuard Key Log',
    0x5a4e574b: 'ZigBee NWK Key',  # ZigBee Specification
    0x5a415053: 'ZigBee APS Key',  # ZigBee Specification
}  # type: dict[int, str]


class SecretsType(Vendor):
    """Secrets Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.pcapng.secrets_type.DATA`).

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
            "extend_enum(cls, 'Unassigned_0x%08x' % value, value)",
            'return cls(value)'
        ]
        for code, name in DATA.items():
            renm = self.rename(name, code)  # type: ignore[arg-type]
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == '__main__':
    sys.exit(SecretsType())  # type: ignore[arg-type]
