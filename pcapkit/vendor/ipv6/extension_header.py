# -*- coding: utf-8 -*-
"""IPv6 Extension Header Types"""

import collections
import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['ExtensionHeader']

LINE = lambda NAME, DOCS, ENUM: '''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""{}"""

from aenum import IntEnum, extend_enum


class {}(IntEnum):
    """Enumeration class for {}."""
    _ignore_ = '{} _'
    {} = vars()

    # {}
    {}

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return {}(key)
        if key not in {}._member_map_:  # pylint: disable=no-member
            extend_enum({}, key, default)
        return {}[key]
'''.format(DOCS, NAME, NAME, NAME, NAME, DOCS, ENUM, NAME, NAME, NAME, NAME)


class ExtensionHeader(Vendor):
    """IPv6 Extension Header Types"""

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
            flag = item[3]
            if flag != 'Y':
                continue

            name = item[1]
            rfcs = item[4]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc:
                    temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
                else:
                    temp.append('[{}]'.format(rfc))
            lrfc = re.sub(r'( )( )*', ' ',
                          " {}".format(''.join(temp)).replace('\n', ' ')) if rfcs else ''

            subd = re.sub(r'( )( )*', ' ', item[2].replace('\n', ' '))
            desc = ' {}'.format(subd) if item[2] else ''

            split = name.split(' (', 1)
            if len(split) == 2:
                name, cmmt = split[0], " ({}".format(split[1])
            else:
                name, cmmt = name, ''

            try:
                code, _ = item[0], int(item[0])
                if not name:
                    name, desc = item[2], ''
                renm = self.rename(name, code, original=item[1])

                pres = "{}[{!r}] = {}".format(self.NAME, renm, code)
                sufs = "#{}{}{}".format(lrfc, desc, cmmt) if lrfc or desc or cmmt else ''

                if len(pres) > 74:
                    sufs = "\n{}{}".format(' '*80, sufs)

                enum.append('{}{}'.format(pres.ljust(76), sufs))
            except ValueError:
                start, stop = item[0].split('-')
                if not name:
                    name, desc = item[2], ''

                miss.append('if {} <= value <= {}:'.format(start, stop))
                if lrfc or desc or cmmt:
                    miss.append('    #{}{}{}'.format(lrfc, desc, cmmt))
                miss.append("    extend_enum(cls, '{} [%d]' % value, value)".format(name))
                miss.append('    return cls(value)')
        return enum

    def context(self, data):
        enum = self.process(data)
        ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
        return LINE(self.NAME, self.DOCS, ENUM)


if __name__ == '__main__':
    ExtensionHeader()
