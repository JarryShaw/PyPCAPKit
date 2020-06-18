# -*- coding: utf-8 -*-
"""IPv6 Seed-ID Types"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['SeedID']

#: Seed-ID type registry [:rfc:`7731`].
DATA = {
    0b00: 'IPv6 Source Address',                   # [RFC 7731]
    0b01: '16-Bit Unsigned Integer',               # [RFC 7731]
    0b10: '64-Bit Unsigned Integer',               # [RFC 7731]
    0b11: '128-Bit Unsigned Integer',              # [RFC 7731]
}


class SeedID(Vendor):
    """Seed-ID Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b00 <= value <= 0b11'

    def request(self):  # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Dict[int, str]: Registry data (:attr:`~pcapkit.vendor.ipv6.seed_id.DATA`).

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
            "extend_enum(cls, 'Unassigned_0b%s' % bin(value)[2:].zfill(2), value)",
            'return cls(value)'
        ]
        for code, name in data.items():
            code = f'0b{bin(code)[2:].zfill(2)}'
            renm = self.rename(name, code).upper()
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == "__main__":
    SeedID()
