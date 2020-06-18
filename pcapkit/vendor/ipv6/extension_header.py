# -*- coding: utf-8 -*-
"""IPv6 Extension Header Types"""

import collections
import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['ExtensionHeader']

LINE = lambda NAME, DOCS, ENUM: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""{DOCS}"""

from aenum import IntEnum, extend_enum

__all__ = ['{NAME}']


class {NAME}(IntEnum):
    """[{NAME}] {DOCS}"""

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

    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv'

    def count(self, data):
        """Count field records.

        Args:
            data (List[str]): CSV data.

        Returns:
            Counter: Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: self.safe_name(item[1] or item[2]),  # pylint: disable=map-builtin-not-iterating
                                       filter(lambda item: len(item[0].split('-')) != 2, reader)))  # pylint: disable=filter-builtin-not-iterating

    def process(self, data):
        """Process CSV data.

        Args:
            data (List[str]): CSV data.

        Returns:
            List[str]: Enumeration fields.
            List[str]: Missing fields.

        """
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
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            lrfc = re.sub(r'( )( )*', ' ', f" {''.join(temp)}".replace('\n', ' ')) if rfcs else ''

            subd = re.sub(r'( )( )*', ' ', item[2].replace('\n', ' '))
            tmp1 = f' {subd}' if item[2] else ''

            split = name.split(' (', 1)
            if len(split) == 2:
                name, cmmt = split[0], f" ({split[1]}"
            else:
                name, cmmt = name, ''  # pylint: disable=self-assigning-variable

            if not name:
                name, tmp1 = item[2], ''
            desc = self.wrap_comment(f'{name}{lrfc}{tmp1}{cmmt}')

            try:
                code, _ = item[0], int(item[0])
                if not name:
                    name, desc = item[2], ''
                renm = self.rename(name, code, original=item[1])

                pres = f"{renm} = {code}"
                sufs = f"#: {desc}"

                #if len(pres) > 74:
                #    sufs = f"\n{' '*80}{sufs}"

                #enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    extend_enum(cls, '{self.safe_name(name)}_%d' % value, value)")
                miss.append('    return cls(value)')
        return enum

    def context(self, data):
        enum = self.process(data)
        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum))
        return LINE(self.NAME, self.DOCS, ENUM)


if __name__ == '__main__':
    ExtensionHeader()
