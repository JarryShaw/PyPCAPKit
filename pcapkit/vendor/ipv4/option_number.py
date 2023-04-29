# -*- coding: utf-8 -*-
"""IP Option Numbers
=======================

.. module:: pcapkit.vendor.ipv4.option_number

This module contains the vendor crawler for **IP Option Numbers**,
which is automatically generating :class:`pcapkit.const.ipv4.option_number.OptionNumber`.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['OptionNumber']


class OptionNumber(Vendor):
    """IP Option Numbers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ip-parameters/ip-parameters-1.csv'

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: self.safe_name(item[4]),
                                       filter(lambda item: len(item[3].split('-')) != 2, reader)))

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
            "return extend_enum(cls, 'Unassigned_%d' % value, value)",
        ]
        for item in reader:
            code = item[3]
            dscp = item[4]
            rfcs = item[5]

            temp = []  # type: list[str]
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if re.match(r'\d+', rfc):
                    continue
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''

            abbr, name = [s.strip() for s in dscp.split('- ')]
            tmp2 = re.sub(r'\[\d+\]', '', name).strip()

            if abbr:
                name = f', {tmp2}' if tmp2 else ''
                desc = self.wrap_comment(f'``{abbr}``{name}{tmp1}')
            else:
                name = tmp2 or ''
                desc = self.wrap_comment(f'{name}{tmp1}')

            renm = self.rename(abbr or 'Unassigned', code, original=dscp)
            pres = f"{renm} = {code}"
            sufs = f'#: {desc}'

            #if len(pres) > 74:
            #    sufs = f"\n{' '*80}{sufs}"

            #enum.append(f'{pres.ljust(76)}{sufs}')
            enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(OptionNumber())  # type: ignore[arg-type]
