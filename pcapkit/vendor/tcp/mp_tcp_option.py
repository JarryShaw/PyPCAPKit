# -*- coding: utf-8 -*-
"""Multipath TCP options [:rfc:`6824`]"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['MPTCPOption']

#: Multipath TCP options.
DATA = {   # [RFC 6824]
    0: 'MP_CAPABLE',
    1: 'MP_JOIN',
    2: 'DSS',
    3: 'ADD_ADDR',
    4: 'REMOVE_ADDR',
    5: 'MP_PRIO',
    6: 'MP_FAIL',
    7: 'MP_FASTCLOSE',
}


class MPTCPOption(Vendor):
    """Multipath TCP options [:rfc:`6824`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'

    def request(self):  # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Dict[int, str]: Multipath TCP options, i.e. :data:`~pcapkit.vendor.tcp.mp_tcp_option.DATA`.

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
        """Process CSV data.

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
    MPTCPOption()
