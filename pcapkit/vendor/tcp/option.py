# -*- coding: utf-8 -*-
"""TCP Option Kind Numbers
=============================

.. module:: pcapkit.vendor.tcp.option

This module contains the vendor crawler for **TCP Option Kind Numbers**,
which is automatically generating :class:`pcapkit.const.tcp.option.Option`.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['Option']


class Option(Vendor):
    """TCP Option Kind Numbers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/tcp-parameters/tcp-parameters-1.csv'

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: self.safe_name(item[2]), reader))

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
            dscp = item[2]
            rfcs = item[3]

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
            desc = self.wrap_comment(re.sub(r'(\[(\*+)\])|(\[(\d+)\])', r'',
                                            re.sub(r'\r*\n', ' ', f'{dscp}{tmp1}', re.MULTILINE)))

            name = dscp.split(' (')[0]
            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name or 'Unassigned', code, original=dscp)

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
                miss.append(f"    return extend_enum(cls, '{name}_%d' % value, value)")
        return enum, miss


if __name__ == '__main__':
    sys.exit(Option())  # type: ignore[arg-type]
