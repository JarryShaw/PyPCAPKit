# -*- coding: utf-8 -*-
"""HIP Parameter Types"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Parameter']


class Parameter(Vendor):
    """HIP Parameter Types"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-4.csv'

    def process(self, data):
        reader = csv.reader(data)
        next(reader)  # header

        enum = list()
        miss = list()
        for item in reader:
            long = item[1]
            plen = item[2]
            rfcs = item[3]

            match = re.match(r'(\w*) *(\(.*\))*', long)
            group = match.groups()

            name = group[0]
            cmmt = ' {}'.format(group[1]) if group[1] else ''
            plen = ' {}'.format(plen) if re.match(r'\d+', plen) else ''

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc:
                    temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
                else:
                    temp.append('[{}]'.format(rfc))
            lrfc = " {}".format(''.join(temp)) if rfcs else ''

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code, original=long)

                pres = "{}[{!r}] = {}".format(self.NAME, renm, code)
                sufs = "#{}{}{}".format(lrfc, plen, cmmt) if lrfc or cmmt or plen else ''

                if len(pres) > 74:
                    sufs = "\n{}{}".format(' '*80, sufs)

                enum.append('{}{}'.format(pres.ljust(76), sufs))
            except ValueError:
                start, stop = item[0].split('-')

                miss.append('if {} <= value <= {}:'.format(start, stop))
                if lrfc or cmmt or plen:
                    miss.append("#{}{}{}".format(lrfc, plen, cmmt))
                miss.append("    extend_enum(cls, '{} [%d]' % value, value)".format(name))
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Parameter()
