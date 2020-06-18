# -*- coding: utf-8 -*-
"""IPv4 ToS ECN Field"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['ToSECN']

#: ToS registry.
DATA = {
    0b00: 'Not-ECT',
    0b01: 'ECT(1)',
    0b10: 'ECT(0)',
    0b11: 'CE',
}


class ToSECN(Vendor):
    """ToS ECN Field"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b00 <= value <= 0b11'

    def request(self):  # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Dict[int, str]: Registry data (:data:`~pcapkit.vendor.ipv4.tos_ecn.DATA`).

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

    def rename(self, name, code):  # pylint: disable=arguments-differ
        """Rename duplicated fields.

        Args:
            name (str): Field name.
            code (int): Field code.

        Returns:
            str: Revised field name.

        """
        if self.record[self.safe_name(name)] > 1:
            name = f'{name} [0b{bin(code)[2:].zfill(2)}]'
        return self.safe_name(name)

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
        for code, name in DATA.items():
            renm = self.rename(name, code)
            enum.append(f"{renm} = 0b{bin(code)[2:].zfill(2)}".ljust(76))
        return enum, miss


if __name__ == "__main__":
    ToSECN()
