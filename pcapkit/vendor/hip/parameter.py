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
            cmmt = f' {group[1]}' if group[1] else ''
            plen = f' {plen}' if re.match(r'\d+', plen) else ''

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc:
                    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                else:
                    temp.append(f'[{rfc}]')
            lrfc = f" {''.join(temp)}" if rfcs else ''

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code, original=long)

                pres = f"{self.NAME}[{renm!r}] = {code}"
                sufs = f"#{lrfc}{plen}{cmmt}" if lrfc or cmmt or plen else ''

                if len(pres) > 74:
                    sufs = f"\n{' '*80}{sufs}"

                enum.append(f'{pres.ljust(76)}{sufs}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                if lrfc or cmmt or plen:
                    miss.append(f"#{lrfc}{plen}{cmmt}")
                miss.append(f"    extend_enum(cls, '{name} [%d]' % value, value)")
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Parameter()
