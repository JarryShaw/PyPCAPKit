# -*- coding: utf-8 -*-
"""L2TP Type"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['Type']

#: L2TP packet types.
DATA = {
    0:  'Control',
    1:  'Data',
}


class Type(Vendor):
    """L2TP Type"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 1'

    def request(self):  # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Dict[int, str]: TCP checksum options, i.e. :data:`~pcapkit.vendor.tcp.checksum.DATA`.

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
    Type()
