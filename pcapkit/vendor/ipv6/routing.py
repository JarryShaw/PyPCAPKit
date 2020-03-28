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
                cmmt = f' {split[1][:-1]}'
            else:
                name, cmmt = re.sub(r'\[\d+\]', '', long).strip(), ''

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc:
                    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                else:
                    temp.append(f'[{rfc}]')
            lrfc = f" {''.join(temp)}" if rfcs else ''

            try:
                code = int(item[0])
                renm = self.rename(name, code)

                pres = f"{self.NAME}[{renm!r}] = {code}"
                sufs = f"#{lrfc}{cmmt}" if lrfc or cmmt else ''

                if len(pres) > 74:
                    sufs = f"\n{' '*80}{sufs}"

                enum.append(f'{pres.ljust(76)}{sufs}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                if lrfc or cmmt:
                    miss.append(f'    #{lrfc}{cmmt}')
                miss.append(f"    extend_enum(cls, '{name} [%d]' % value, value)")
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Routing()
