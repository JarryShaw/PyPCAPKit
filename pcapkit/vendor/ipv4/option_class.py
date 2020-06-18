# -*- coding: utf-8 -*-
"""IPv4 Option Classes"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['OptionClass']

#: Option class registry.
DATA = {
    0: 'control',
    1: 'reserved for future use',
    2: 'debugging and measurement',
    3: 'reserved for future use',
}


def binary(code):
    """Convert code to binary form."""
    return f'0b{bin(code)[2:].upper().zfill(8)}'


class OptionClass(Vendor):
    """Option Classes"""

    #: Value limit checker.s
    FLAG = 'isinstance(value, int) and 0 <= value <= 3'

    def request(self):  # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Dict[int, str]: Registry data (:data:`~pcapkit.vendor.ipv4.option_class.DATA`).

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
    OptionClass()
