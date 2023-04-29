# -*- coding: utf-8 -*-
"""HIP Packet Types
======================

.. module:: pcapkit.const.hip.packet

This module contains the vendor crawler for **HIP Packet Types**,
which is automatically generating :class:`pcapkit.const.hip.packet.Packet`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Packet']


class Packet(Vendor):
    """HIP Packet Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 127'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-1.csv'

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

            if ' - ' in long:
                name, cmmt = long.split(' -')
            elif ' (' in long:
                cmmt, name = long.strip(')').split(' (')
                cmmt = f' ({cmmt})'
            else:
                name, cmmt = long, ''

            temp = []  # type: list[str]
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''
            desc = self.wrap_comment(f"{name}{cmmt}{tmp1}")

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code, original=long)

                pres = f"{renm} = {code}"
                sufs = f'#: {desc}'

                #if len(pres) > 74:
                #    sufs = f"\n{' '*80}{sufs}"

                #enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    # {desc}')
                miss.append(f"    return extend_enum(cls, '{self.safe_name(name)}_%d' % value, value)")
        return enum, miss


if __name__ == '__main__':
    sys.exit(Packet())  # type: ignore[arg-type]
