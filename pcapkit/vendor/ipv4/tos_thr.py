# -*- coding: utf-8 -*-
"""IPv4 TOS (DS Field) Throughput"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['TOS_THR']

DATA = {
    0: 'Normal',
    1: 'High',
}


class TOS_THR(Vendor):
    """TOS (DS Field) Throughput"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 1'

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
        for code, name in DATA.items():
            renm = self.rename(name, code).upper()
            enum.append(f"{self.NAME}[{renm!r}] = {code}".ljust(76))
        return enum, miss


if __name__ == "__main__":
    TOS_THR()
