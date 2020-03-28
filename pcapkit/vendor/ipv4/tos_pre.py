# -*- coding: utf-8 -*-
"""IPv4 TOS (DS Field) Precedence"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['TOS_PRE']

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


class TOS_PRE(Vendor):
    """TOS (DS Field) Precedence"""

    FLAG = 'isinstance(value, int) and 0b000 <= value <= 0b111'

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
            renm = self.rename(name, code)
            enum.append(f"{self.NAME}[{renm!r}] = {code}".ljust(76))
        return enum, miss


if __name__ == "__main__":
    TOS_PRE()
