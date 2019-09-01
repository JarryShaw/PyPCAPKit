# -*- coding: utf-8 -*-
"""Ethertype IEEE 802 Numbers"""

import collections
import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['EtherType']


class EtherType(Vendor):
    """Ethertype IEEE 802 Numbers"""

    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
    LINK = 'https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers-1.csv'

    def count(self, data):
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: item[4],  # pylint: disable=map-builtin-not-iterating
                                       filter(lambda item: len(item[1].split('-')) != 2, reader)))  # pylint: disable=filter-builtin-not-iterating

    def rename(self, name, code):  # pylint: disable=arguments-differ
        if self.record[name] > 1:
            name = '{} [0x{}]'.format(name, code)
        return name

    def process(self, data):
        reader = csv.reader(data)
        next(reader)  # header

        enum = list()
        miss = list()
        for item in reader:
            name = item[4]
            rfcs = item[5]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc:
                    temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
                else:
                    temp.append('[{}]'.format(rfc))
            desc = re.sub(r'( )( )*', ' ', "# {}".format(''.join(temp)).replace('\n', ' ')) if rfcs else ''

            try:
                code, _ = item[1], int(item[1], base=16)
                renm = re.sub(r'( )( )*', ' ', self.rename(name, code).replace('\n', ' '))

                pres = '{}[{!r}] = 0x{}'.format(self.NAME, renm, code)
                sufs = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                if len(pres) > 74:
                    sufs = "\n{}{}".format(' '*80, sufs)

                enum.append('{}{}'.format(pres.ljust(76), sufs))
            except ValueError:
                start, stop = item[1].split('-')
                more = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                miss.append('if 0x{} <= value <= 0x{}:'.format(start, stop))
                if more:
                    miss.append('    {}'.format(more))
                miss.append(
                    "    extend_enum(cls, '{} [0x%s]' % hex(value)[2:].upper().zfill(4), value)".format(name))
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    EtherType()
