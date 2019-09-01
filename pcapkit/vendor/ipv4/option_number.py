# -*- coding: utf-8 -*-
"""IPv4 Option Numbers"""

import collections
import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['OptionNumber']


class OptionNumber(Vendor):
    """IP Option Numbers"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    LINK = 'https://www.iana.org/assignments/ip-parameters/ip-parameters-1.csv'

    def count(self, data):
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: item[4],  # pylint: disable=map-builtin-not-iterating
                                       filter(lambda item: len(item[3].split('-')) != 2, reader)))  # pylint: disable=filter-builtin-not-iterating

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
                    temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
                else:
                    temp.append('[{}]'.format(rfc))
            desc = " {}".format(''.join(temp)) if rfcs else ''

            abbr, name = re.split(r'\W+-\W+', dscp)
            temp = re.sub(r'\[\d+\]', '', name)
            name = ' {}'.format(temp) if temp else ''

            renm = self.rename(abbr or 'Unassigned [{}]'.format(code), code, original=dscp)
            pres = "{}[{!r}] = {}".format(self.NAME, renm, code)
            sufs = '#{}{}'.format(desc, name) if desc or name else ''

            if len(pres) > 74:
                sufs = "\n{}{}".format(' '*80, sufs)

            enum.append('{}{}'.format(pres.ljust(76), sufs))
        return enum, miss


if __name__ == "__main__":
    OptionNumber()
