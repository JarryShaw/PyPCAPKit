# -*- coding: utf-8 -*-
"""IPv4 Classification Level Encodings"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['ClassificationLevel']

DATA = {
    0b0000_0001: 'Reserved [4]',
    0b0011_1101: 'Top Secret',
    0b0101_1010: 'Secret',
    0b1001_0110: 'Confidential',
    0b0110_0110: 'Reserved [3]',
    0b1100_1100: 'Reserved [2]',
    0b1010_1011: 'Unclassified',
    0b1111_0001: 'Reserved [1]',
}


def binary(code):
    return '0b{}'.format(bin(code)[2:].upper().zfill(8))


class ClassificationLevel(Vendor):
    """Classification Level Encodings"""

    FLAG = 'isinstance(value, int) and 0b00000000 <= value <= 0b11111111'

    def request(self):  # pylint: disable=arguments-differ
        return DATA

    def count(self, data):
        return collections.Counter(data.values())  # pylint: disable=dict-values-not-iterating

    def process(self, data):
        enum = list()
        miss = [
            'temp = bin(value)[2:].upper().zfill(8)',
            "extend_enum(cls, 'Unassigned [0b%s]' % (temp[:4]+'_'+temp[4:]), value)",
            'return cls(value)'
        ]
        for code, name in data.items():
            code = binary(code)
            renm = self.rename(name, code)
            enum.append("{}[{!r}] = {}".format(self.NAME, renm, code).ljust(76))
        return enum, miss


if __name__ == "__main__":
    ClassificationLevel()
