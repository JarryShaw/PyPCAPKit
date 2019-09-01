# -*- coding: utf-8 -*-
"""IPv4 TOS ECN FIELD"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['TOS_ECN']

DATA = {
    0b00: 'Not-ECT',
    0b01: 'ECT(1)',
    0b10: 'ECT(0)',
    0b11: 'CE',
}


class TOS_ECN(Vendor):
    """TOS ECN FIELD"""

    FLAG = 'isinstance(value, int) and 0b00 <= value <= 0b11'

    def request(self):  # pylint: disable=arguments-differ
        return DATA

    def count(self, data):
        return collections.Counter(data.values())

    def rename(self, name, code):  # pylint: disable=arguments-differ
        if self.record[name] > 1:
            name = '{} [0b{}]'.format(name, bin(code)[2:].zfill(2))
        return name

    def process(self, data):
        enum = list()
        miss = [
            "extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(2), value)",
            'return cls(value)'
        ]
        for code, name in DATA.items():
            renm = self.rename(name, code)
            enum.append("{}[{!r}] = 0b{}".format(self.NAME, renm, bin(code)[2:].zfill(2)).ljust(76))
        return enum, miss


if __name__ == "__main__":
    TOS_ECN()
