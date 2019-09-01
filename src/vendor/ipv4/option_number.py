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
                    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                else:
                    temp.append(f'[{rfc}]')
            desc = f" {''.join(temp)}" if rfcs else ''

            abbr, name = re.split(r'\W+-\W+', dscp)
            temp = re.sub(r'\[\d+\]', '', name)
            name = f' {temp}' if temp else ''

            renm = self.rename(abbr or f'Unassigned [{code}]', code, original=dscp)
            pres = f"{self.NAME}[{renm!r}] = {code}"
            sufs = f'#{desc}{name}' if desc or name else ''

            if len(pres) > 74:
                sufs = f"\n{' '*80}{sufs}"

            enum.append(f'{pres.ljust(76)}{sufs}')
        return enum, miss


if __name__ == "__main__":
    OptionNumber()
