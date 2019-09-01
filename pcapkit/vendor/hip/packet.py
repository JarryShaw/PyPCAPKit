# -*- coding: utf-8 -*-
"""HIP Packet Types"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Packet']


class Packet(Vendor):
    """HIP Packet Types"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 127'
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-1.csv'

    def process(self, data):
        reader = csv.reader(data)
        next(reader)  # header

        enum = list()
        miss = list()
        for item in reader:
            long = item[1]
            rfcs = item[2]

            if ' - ' in long:
                name, cmmt = long.split(' -')
            elif ' (' in long:
                cmmt, name = " {}".format(long.strip(')')).split(' (')
            else:
                name, cmmt = long, ''

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc:
                    temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
                else:
                    temp.append('[{}]'.format(rfc))
            desc = " {}".format(''.join(temp)) if rfcs else ''

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code, original=long)

                pres = "{}[{!r}] = {}".format(self.NAME, renm, code)
                sufs = '#{}{}'.format(desc, cmmt) if desc or cmmt else ''

                if len(pres) > 74:
                    sufs = "\n{}{}".format(' '*80, sufs)

                enum.append('{}{}'.format(pres.ljust(76), sufs))
            except ValueError:
                start, stop = item[0].split('-')

                miss.append('if {} <= value <= {}:'.format(start, stop))
                if desc or cmmt:
                    miss.append('    #{}{}'.format(desc, cmmt))
                miss.append("    extend_enum(cls, '{} [%d]' % value, value)".format(name))
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Packet()
