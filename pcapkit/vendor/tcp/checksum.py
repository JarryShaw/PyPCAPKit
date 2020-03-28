# -*- coding: utf-8 -*-
"""TCP Checksum [RFC 1146]"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['Checksum']

DATA = {
    0:  'TCP checksum',
    1:  "8-bit Fletcher's algorithm",
    2:  "16-bit Fletcher's algorithm",
    3:  'Redundant Checksum Avoidance',
}


class Checksum(Vendor):
    """TCP Checksum [RFC 1146]"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 255'

    def request(self):  # pylint: disable=arguments-differ
        return DATA

    def count(self, data):
        return collections.Counter(data.values())

    def process(self, data):
        enum = list()
        miss = [
            "extend_enum(cls, 'Unassigned [%d]' % value, value)",
            'return cls(value)'
        ]
        for code, name in data.items():
            renm = self.rename(name, code)
            enum.append(f"{self.NAME}[{renm!r}] = {code}".ljust(76))
        return enum, miss


if __name__ == "__main__":
    Checksum()
