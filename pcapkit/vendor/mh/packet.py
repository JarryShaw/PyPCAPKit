# -*- coding: utf-8 -*-
"""Mobility Header Types - for the MH Type field in the Mobility Header
==========================================================================

This module contains the vendor crawler for **Mobility Header Types - for the MH Type field in the Mobility Header**,
which is automatically generating :class:`pcapkit.const.mh.packet.Packet`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Packet']


class Packet(Vendor):
    """Mobility Header Types - for the MH Type field in the Mobility Header"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/mobility-parameters/mobility-parameters-1.csv'

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
        miss = [
            "extend_enum(cls, 'Unassigned_%d' % value, value)",
            'return cls(value)'
        ]
        for item in reader:
            long = item[1]
            rfcs = item[2]

            temp = []  # type: list[str]
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
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

            code, _ = item[0], int(item[0])
            renm = self.rename(name, code, original=long)

            pres = f"{renm} = {code}"
            sufs = f'#: {desc}'

            # if len(pres) > 74:
            #     sufs = f"\n{' '*80}{sufs}"

            # enum.append(f'{pres.ljust(76)}{sufs}')
            enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(Packet())
