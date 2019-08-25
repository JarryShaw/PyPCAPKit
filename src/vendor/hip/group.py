# -*- coding: utf-8 -*-

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Group']


class Group(Vendor):
    """Group IDs"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-5.csv'

    def rename(self, name, code, *, original):  # pylint: disable=redefined-outer-name, arguments-differ
        if self.record[original] > 1:
            return f'{name} [{code}]'
        return name

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
                name = split[0]
                cmmt = f' {split[1][:-1]}'
            else:
                name, cmmt = long, ''

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

                pres = f"{self.NAME}[{renm!r}] = {code}".ljust(76)
                sufs = f"#{lrfc}{cmmt}" if lrfc or cmmt else ''

                enum.append(f'{pres}{sufs}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                if lrfc or cmmt:
                    miss.append(f'    #{lrfc}{cmmt}')
                miss.append(f"    extend_enum(cls, '{name} [%d]' % value, value)")
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Group()
