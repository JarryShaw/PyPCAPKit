# -*- coding: utf-8 -*-
"""IPv4 Option Classes"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['OptionClass']

DATA = {
    0: 'control',
    1: 'reserved for future use',
    2: 'debugging and measurement',
    3: 'reserved for future use',
}


def binary(code):
    return '0b{}'.format(bin(code)[2:].upper().zfill(8))


class OptionClass(Vendor):
    """Option Classes"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 3'

    def request(self):  # pylint: disable=arguments-differ
        return DATA

    def count(self, data):
        return collections.Counter(data.values())  # pylint: disable=dict-values-not-iterating

    def process(self, data):
        enum = list()
        miss = [
            "extend_enum(cls, 'Unassigned [%d]' % value, value)",
            'return cls(value)'
        ]
        for code, name in data.items():
            renm = self.rename(name, code)
            enum.append("{}[{!r}] = {}".format(self.NAME, renm, code).ljust(76))
        return enum, miss


if __name__ == "__main__":
    OptionClass()
