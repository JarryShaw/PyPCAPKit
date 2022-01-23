# -*- coding: utf-8 -*-
"""IPv4 TS Flag"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['TSFlag']

#: TS flag registry [:rfc:`719#section-3.1`].
DATA = {
    0: 'Timestamp Only',
    1: 'IP with Timestamp',
    3: 'Prespecified IP with Timestamp',
}


class TSFlag(Vendor):
    """TS Flag"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b0000 <= value <= 0b1111'

    def request(self):  # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Dict[int, str]: Registry data (:data:`~pcapkit.vendor.ipv4.qs_function.DATA`).

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
        for code, name in DATA.items():
            renm = self.rename(name, code)
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == "__main__":
    TSFlag()
