# -*- coding: utf-8 -*-
"""Destination Options and Hop-by-Hop Options
================================================

.. module:: pcapkit.vendor.ipv6.option

This module contains the vendor crawler for **Destination Options and Hop-by-Hop Options**,
which is automatically generating :class:`pcapkit.const.ipv6.option.Option`.

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
    """Destination Options and Hop-by-Hop Options"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters-2.csv'

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: self.safe_name(item[4]), reader))

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
            "return extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(2), value)",
        ]
        for item in reader:
            if not item[0]:
                continue

            code = item[0]
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

            splt = re.split(r' \[\d+\]', dscp)[0]
            name = re.sub(r'.* \((.*)\)', r'\1', splt)
            if re.fullmatch(r'[0-9a-zA-Z]+', name) is None or name.upper() == 'DEPRECATED':
                name = re.sub(r'(.*) \(.*\)', r'\1', splt)

            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', f'{splt}{tmp1}', re.MULTILINE))
            renm = self.rename(name or 'Unassigned', code, original=dscp)

            pres = f"{renm} = {code}"
            sufs = f'#: {desc}'

            #if len(pres) > 74:
            #    sufs = f"\n{' '*80}{sufs}"

            #enum.append(f'{pres.ljust(76)}{sufs}')
            enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(Option())  # type: ignore[arg-type]
