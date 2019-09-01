# -*- coding: utf-8 -*-
"""Transport Layer Protocol Numbers"""

import collections
import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['TransType']


class TransType(Vendor):
    """Transport Layer Protocol Numbers"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    LINK = 'https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv'

    def count(self, data):
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: item[1] or item[2],  # pylint: disable=map-builtin-not-iterating
                                       filter(lambda item: len(item[0].split('-')) != 2, reader)))  # pylint: disable=filter-builtin-not-iterating

    def process(self, data):
        reader = csv.reader(data)
        next(reader)  # header

        enum = list()
        miss = list()
        for item in reader:
            long = item[1]
            rfcs = item[4]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc:
                    temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
                else:
                    temp.append('[{}]'.format(rfc))
            lrfc = re.sub(r'( )( )*', ' ', " {}".format(''.join(temp)).replace('\n', ' ')) if rfcs else ''

            subd = re.sub(r'( )( )*', ' ', item[2].replace('\n', ' '))
            desc = ' {}'.format(subd) if item[2] else ''

            split = long.split(' (', 1)
            if len(split) == 2:
                name, cmmt = split[0], " ({}".format(split[1])
            else:
                name, cmmt = long, ''
            if not name:
                name, desc = item[2], ''

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code, original=long)

                pres = "{}[{!r}] = {}".format(self.NAME, renm, code)
                sufs = "#{}{}{}".format(lrfc, desc, cmmt) if lrfc or desc or cmmt else ''

                if len(pres) > 74:
                    sufs = "\n{}{}".format(' '*80, sufs)

                enum.append('{}{}'.format(pres.ljust(76), sufs))
            except ValueError:
                start, stop = item[0].split('-')

                miss.append('if {} <= value <= {}:'.format(start, stop))
                if lrfc or desc or cmmt:
                    miss.append('    #{}{}{}'.format(lrfc, desc, cmmt))
                miss.append("    extend_enum(cls, '{} [%d]' % value, value)".format(name))
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    TransType()
