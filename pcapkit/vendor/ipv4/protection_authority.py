# -*- coding: utf-8 -*-
"""IPv4 Protection Authority Bit Assignments"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['ProtectionAuthority']

#: Protection authority registry.
DATA = {
    0: 'GENSER',
    1: 'SIOP-ESI',
    2: 'SCI',
    3: 'NSA',
    4: 'DOE',
    5: 'Unassigned',
    6: 'Unassigned',
    7: 'Field Termination Indicator',
}


class ProtectionAuthority(Vendor):
    """Protection Authority Bit Assignments"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 7'

    def request(self):  # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Dict[int, str]: Registry data (:data:`~pcapkit.vendor.ipv4.protection_authority.DATA`).

        """
        return DATA

    def count(self, data):
        """Count field records.

        Args:
            data (Dict[int, str]): Registry data.

        Returns:
            Counter: Field recordings.

        """
        return collections.Counter(map(self.safe_name, data.values()))  # pylint: disable=dict-values-not-iterating,map-builtin-not-iterating

    def process(self, data):
        """Process registry data.

        Args:
            data (Dict[int, str]): Registry data.

        Returns:
            List[str]: Enumeration fields.
            List[str]: Missing fields.

        """
        enum = list()
        miss = [
            "extend_enum(cls, 'Unassigned_%d' % value, value)",
            'return cls(value)'
        ]
        for code, name in data.items():
            renm = self.rename(name, code)
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == "__main__":
    ProtectionAuthority()
