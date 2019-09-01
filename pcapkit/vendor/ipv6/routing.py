# -*- coding: utf-8 -*-
"""IPv6 Routing Types"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Routing']


class Routing(Vendor):
    """IPv6 Routing Types"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    LINK = 'https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters-3.csv'

    def process(self, data):
        reader = csv.reader(data)
        next(reader)  # header

        enum = list()
        miss = list()
        for item in reader:
            long = item[1]
            rfcs = item[2]

            split = long.split(' (')
            if len(split) == 2:
                name = re.sub(r'\[\d+\]', '', split[0]).strip()
                cmmt = ' {}'.format(split[1][:-1])
            else:
                name, cmmt = re.sub(r'\[\d+\]', '', long).strip(), ''

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc:
                    temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
                else:
                    temp.append('[{}]'.format(rfc))
            lrfc = " {}".format(''.join(temp)) if rfcs else ''

            try:
                code = int(item[0])
                renm = self.rename(name, code)

                pres = "{}[{!r}] = {}".format(self.NAME, renm, code)
                sufs = "#{}{}".format(lrfc, cmmt) if lrfc or cmmt else ''

                if len(pres) > 74:
                    sufs = "\n{}{}".format(' '*80, sufs)

                enum.append('{}{}'.format(pres.ljust(76), sufs))
            except ValueError:
                start, stop = item[0].split('-')

                miss.append('if {} <= value <= {}:'.format(start, stop))
                if lrfc or cmmt:
                    miss.append('    #{}{}'.format(lrfc, cmmt))
                miss.append("    extend_enum(cls, '{} [%d]' % value, value)".format(name))
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Routing()
