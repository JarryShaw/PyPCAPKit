# -*- coding: utf-8 -*-
"""IPv6 TaggerID Types"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['TaggerID']


class TaggerID(Vendor):
    """TaggerID Types"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 7'
    LINK = 'https://www.iana.org/assignments/ipv6-parameters/taggerId-types.csv'

    def process(self, data):
        reader = csv.reader(data)
        next(reader)  # header

        enum = list()
        miss = list()
        for item in reader:
            name = item[1] or item[2]
            rfcs = item[3]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc:
                    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                else:
                    temp.append(f'[{rfc}]')
            desc = f"# {''.join(temp)}" if rfcs else ''

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code)

                pres = f"{self.NAME}[{renm!r}] = {code}"
                sufs = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                if len(pres) > 74:
                    sufs = f"\n{' '*80}{sufs}"

                enum.append(f'{pres.ljust(76)}{sufs}')
            except ValueError:
                start, stop = item[0].split('-')
                more = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                miss.append(f'if {start} <= value <= {stop}:')
                if more:
                    miss.append(f'    {more}')
                miss.append(f"    extend_enum(cls, '{name} [%d]' % value, value)")
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == '__main__':
    TaggerID()
