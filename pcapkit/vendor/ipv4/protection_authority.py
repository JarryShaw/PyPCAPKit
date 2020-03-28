# -*- coding: utf-8 -*-
"""IPv4 Protection Authority Bit Assignments"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['ProtectionAuthority']

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

    FLAG = 'isinstance(value, int) and 0 <= value <= 7'

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
    ProtectionAuthority()
