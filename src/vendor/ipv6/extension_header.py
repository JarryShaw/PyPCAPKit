# -*- coding: utf-8 -*-

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['ExtensionHeader']

LINE = lambda NAME, DOCS, ENUM: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long

from aenum import IntEnum, extend_enum


class {NAME}(IntEnum):
    """Enumeration class for {NAME}."""
    _ignore_ = '{NAME} _'
    {NAME} = vars()

    # {DOCS}
    {ENUM}

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return {NAME}(key)
        if key not in {NAME}._member_map_:  # pylint: disable=no-member
            extend_enum({NAME}, key, default)
        return {NAME}[key]
'''


class ExtensionHeader(Vendor):
    """IPv6 Extension Header Types"""

    LINK = 'https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv'

    def rename(self, name, code, *, original):  # pylint: disable=arguments-differ
        if self.record[original] > 1:
            return f'{name} [{code}]'
        return name

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
                    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                else:
                    temp.append(f'[{rfc}]')
            lrfc = re.sub(r'( )( )*', ' ',
                          f" {''.join(temp)}".replace('\n', ' ')) if rfcs else ''

            subd = re.sub(r'( )( )*', ' ', item[2].replace('\n', ' '))
            desc = f' {subd}' if item[2] else ''

            split = name.split(' (', 1)
            if len(split) == 2:
                name, cmmt = split[0], f" ({split[1]}"
            else:
                name, cmmt = name, ''

            try:
                code, _ = item[0], int(item[0])
                if not name:
                    name, desc = item[2], ''
                renm = self.rename(name, code, original=item[1])

                pres = f"{self.NAME}[{renm!r}] = {code}".ljust(76)
                sufs = f"#{lrfc}{desc}{cmmt}" if lrfc or desc or cmmt else ''

                enum.append(f'{pres}{sufs}')
            except ValueError:
                start, stop = item[0].split('-')
                if not name:
                    name, desc = item[2], ''

                miss.append(f'if {start} <= value <= {stop}:')
                if lrfc or desc or cmmt:
                    miss.append(f'    #{lrfc}{desc}{cmmt}')
                miss.append(f"    extend_enum(cls, '{name} [%d]' % value, value)")
                miss.append('    return cls(value)')
        return enum

    def context(self, data):
        enum = self.process(data)
        ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
        return LINE(self.NAME, self.DOCS, ENUM)


if __name__ == '__main__':
    ExtensionHeader()
