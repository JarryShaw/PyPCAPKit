# -*- coding: utf-8 -*-
"""CGA Extension Type Tags
=============================

.. module:: pcapkit.vendor.mh.cga_type

This module contains the vendor crawler for **CGA Extension Type Tags**,
which is automatically generating :class:`pcapkit.const.mh.cga_type.CGAType`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['CGAType']


class CGAType(Vendor):
    """CGA Extension Type Tags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/cga-message-types/cga-message-types-1.csv'

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
            "return extend_enum(cls, 'Tag_%s' % ('_'.join(__import__('textwrap').wrap('%032x' % value, 4))), value)",
        ]
        for item in reader:
            long = item[0]
            rfcs = item[1]

            temp = []  # type: list[str]
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    # temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''

            name = 'Tag_%s' % long[2:].replace(' ', '_')
            desc = self.wrap_comment(f'{long}{tmp1}')

            pres = f"{name} = {long.replace(' ', '_')}"
            sufs = f'#: {desc}'

            # if len(pres) > 74:
            #     sufs = f"\n{' '*80}{sufs}"

            # enum.append(f'{pres.ljust(76)}{sufs}')
            enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(CGAType())  # type: ignore[arg-type]
