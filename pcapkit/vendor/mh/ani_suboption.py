# -*- coding: utf-8 -*-
"""Access Network Information (ANI) Sub-Option Type Values
=============================================================

.. module:: pcapkit.vendor.mh.ani_suboption

This module contains the vendor crawler for **Access Network Information (ANI) Sub-Option Type Values**,
which is automatically generating :class:`pcapkit.const.mh.ani_suboption.ANISuboption`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['ANISuboption']


class ANISuboption(Vendor):
    """Access Network Information (ANI) Sub-Option Type Values"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/mobility-parameters/ani.csv'

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields and missing fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = []  # type: list[str]
        miss = []  # type: list[str]
        for item in reader:
            long = item[1]
            rfcs = item[2]

            temp = []  # type: list[str]
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    # temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''

            split = long.split(' (', 1)
            if len(split) == 2:
                name = split[0]
                cmmt = f" ({split[1]}"
            else:
                name, cmmt = long, ''
            desc = self.wrap_comment(f'{name}{cmmt}{tmp1}')

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name.replace('sub-option', '').strip(),
                                   code, original=long)

                pres = f"{renm} = {code}"
                sufs = f'#: {desc}'

                # if len(pres) > 74:
                #     sufs = f"\n{' '*80}{sufs}"

                # enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return extend_enum(cls, '{self.safe_name(name)}_%d' % value, value)")
        return enum, miss


if __name__ == '__main__':
    sys.exit(ANISuboption())  # type: ignore[arg-type]
