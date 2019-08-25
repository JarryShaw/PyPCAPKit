# -*- coding: utf-8 -*-

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['OptionClass']

DATA = {
    0: 'control',
    1: 'reserved for future use',
    2: 'debugging and measurement',
    3: 'reserved for future use',
}

LINE = lambda NAME, DOCS, FLAG, ENUM, MISS: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long

from aenum import IntEnum, extend_enum


class {NAME}(IntEnum):
    """Enumeration class for {NAME}."""
    _ignore_ = '{NAME} _'
    {NAME} = vars()

    # {DOCS}
    {ENUM}

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return {NAME}(key)
        if key not in {NAME}._member_map_:  # pylint: disable=no-member
            extend_enum({NAME}, key, default)
        return {NAME}[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not ({FLAG}):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        {MISS}
'''


def binary(code):
    return f'0b{bin(code)[2:].upper().zfill(8)}'


class OptionClass(Vendor):
    """Option Classes"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 3'

    def request(self):
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
            enum.append(f"{self.NAME}[{renm!r}] = {code}".ljust(76))
        return enum, miss

    def context(self, data):
        enum, miss = self.process(data)

        ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
        MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))

        return LINE(self.NAME, self.DOCS, self.FLAG, ENUM, MISS)


if __name__ == "__main__":
    OptionClass()
