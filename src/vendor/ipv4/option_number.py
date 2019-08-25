# -*- coding: utf-8 -*-

import collections
import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['OptionNumber']

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


class OptionNumber(Vendor):
    """IP Option Numbers"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    LINK = 'https://www.iana.org/assignments/ip-parameters/ip-parameters-1.csv'

    def count(self, data):
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: item[4],  # pylint: disable=map-builtin-not-iterating
                                       filter(lambda item: len(item[3].split('-')) != 2, reader)))  # pylint: disable=filter-builtin-not-iterating

    def rename(self, name, code, *, original):  # pylint: disable=arguments-differ
        if self.record[original] > 1:
            return f'{name} [{code}]'
        return name

    def process(self, data):
        reader = csv.reader(data)
        next(reader)  # header

        enum = list()
        miss = [
            "extend_enum(cls, 'Unassigned [%d]' % value, value)",
            'return cls(value)'
        ]
        for item in reader:
            code = item[3]
            dscp = item[4]
            rfcs = item[5]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if re.match(r'\d+', rfc):
                    continue
                if 'RFC' in rfc:
                    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                else:
                    temp.append(f'[{rfc}]')
            desc = f" {''.join(temp)}" if rfcs else ''

            abbr, name = re.split(r'\W+-\W+', dscp)
            temp = re.sub(r'\[\d+\]', '', name)
            name = f' {temp}' if temp else ''

            renm = self.rename(abbr or f'Unassigned [{code}]', code, original=dscp)
            pres = f"{self.NAME}[{renm!r}] = {code}".ljust(76)
            sufs = f'#{desc}{name}' if desc or name else ''

            enum.append(f'{pres}{sufs}')
        return enum, miss

    def context(self, data):
        enum, miss = self.process(data)

        ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
        MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))

        return LINE(self.NAME, self.DOCS, self.FLAG, ENUM, MISS)


if __name__ == "__main__":
    OptionNumber()
