# -*- coding: utf-8 -*-
"""IPv6 Router Alert Option Values"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['RouterAlert']


class RouterAlert(Vendor):
    """IPv6 Router Alert Option Values"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    LINK = 'https://www.iana.org/assignments/ipv6-routeralert-values/ipv6-routeralert-values-1.csv'

    def process(self, data):
        reader = csv.reader(data)
        next(reader)  # header

        enum = list()
        miss = list()
        for item in reader:
            name = item[1]
            rfcs = item[2]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc:
                    temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
                else:
                    temp.append('[{}]'.format(rfc))
            desc = "# {}".format(''.join(temp)) if rfcs else ''

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code)

                pres = "{}[{!r}] = {}".format(self.NAME, renm, code)
                sufs = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                if len(pres) > 74:
                    sufs = "\n{}{}".format(' '*80, sufs)

                enum.append('{}{}'.format(pres.ljust(76), sufs))
            except ValueError:
                start, stop = map(int, item[0].split('-'))
                more = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                if 'Level' in name:
                    base = name.rstrip('s 0-31')
                    for code in range(start, stop+1):
                        renm = '{} {}'.format(base, code-start)
                        pres = "{}[{!r}] = {}".format(self.NAME, renm, code)

                        if len(pres) > 74:
                            sufs = "\n{}{}".format(' '*80, sufs)

                        enum.append('{}{}'.format(pres.ljust(76), more))
                else:
                    miss.append('if {} <= value <= {}:'.format(start, stop))
                    if more:
                        miss.append('    {}'.format(more))
                    miss.append("    extend_enum(cls, '{} [%d]' % value, value)".format(name))
                    miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    RouterAlert()
