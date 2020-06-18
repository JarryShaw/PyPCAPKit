# -*- coding: utf-8 -*-
"""IPv4 ToS (DS Field) Precedence"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['ToSPrecedence']

#: ToS registry.
DATA = {
    0b111: 'Network Control',
    0b110: 'Internetwork Control',
    0b101: 'CRITIC/ECP',
    0b100: 'Flash Override',
    0b011: 'Flash',
    0b010: 'Immediate',
    0b001: 'Priority',
    0b000: 'Routine',
}


class ToSPrecedence(Vendor):
    """ToS (DS Field) Precedence"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b000 <= value <= 0b111'

    def request(self):  # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Dict[int, str]: Registry data (:data:`~pcapkit.vendor.ipv4.tos_pre.DATA`).

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
    ToSPrecedence()
