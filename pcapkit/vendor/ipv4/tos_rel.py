# -*- coding: utf-8 -*-
"""IPv4 ToS (DS Field) Reliability"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['ToSReliability']

#: ToS registry.
DATA = {
    0: 'Normal',
    1: 'High',
}


class ToSReliability(Vendor):
    """ToS (DS Field) Reliability"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 1'

    def request(self):  # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Dict[int, str]: Registry data (:data:`~pcapkit.vendor.ipv4.tos_rel.DATA`).

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
            renm = self.rename(name, code).upper()
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == "__main__":
    ToSReliability()
