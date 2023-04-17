# -*- coding: utf-8 -*-
"""Handover Initiate Flags
=============================

This module contains the vendor crawler for **Handover Initiate Flags**,
which is automatically generating :class:`pcapkit.const.mh.handover_initiate_flag.HandoverInitiateFlag`.

"""

import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

__all__ = ['HandoverInitiateFlag']

if TYPE_CHECKING:
    from typing import Callable


LINE = lambda NAME, DOCS, FLAG, ENUM, MODL: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""

from aenum import IntFlag

__all__ = ['{NAME}']


class {NAME}(IntFlag):
    """[{NAME}] {DOCS}"""

    {ENUM}

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> '{NAME}':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        """
        if isinstance(key, int):
            return {NAME}(key)
        return {NAME}[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> '{NAME}':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not ({FLAG}):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls(value)
'''  # type: Callable[[str, str, str, str, str], str]


class HandoverInitiateFlag(Vendor):
    """Handover Initiate Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/mobility-parameters/handover-initiate-flags.csv'

    def process(self, data: 'list[str]') -> 'list[str]':  # type: ignore[override] # pylint: disable=arguments-differ,arguments-renamed
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields and missing fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = []  # type: list[str]
        for item in reader:
            name = item[0]
            dscp = item[2]
            rfcs = item[3]

            temp = []  # type: list[str]
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    # temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''

            desc = self.wrap_comment(f'{dscp}{tmp1}')

            code, code_val = item[1], int(item[1], base=16)
            renm = self.rename(name, code)

            pres = f"{renm} = 0x{code_val:02x}"
            sufs = f'#: {desc}'

            # if len(pres) > 74:
            #     sufs = f"\n{' '*80}{sufs}"

            # enum.append(f'{pres.ljust(76)}{sufs}')
            enum.append(f'{sufs}\n    {pres}')
        return enum

    def context(self, data: 'list[str]') -> 'str':  # pylint: disable=arguments-differ,arguments-renamed
        """Generate constant context.

        Args:
            soup: Parsed HTML source.

        Returns:
            Constant context.

        """
        enum = self.process(data)
        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum))
        return LINE(self.NAME, self.DOCS, self.FLAG, ENUM, self.__module__)


if __name__ == '__main__':
    sys.exit(HandoverInitiateFlag())  # type: ignore[arg-type]
