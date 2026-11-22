# -*- coding: utf-8 -*-
"""PPPoE Active Discovery Code Fields
========================================

.. module:: pcapkit.vendor.pppoe.code

This module contains the vendor crawler for **PPPoE Active Discovery Code Fields**,
which is automatically generating :class:`pcapkit.const.pppoe.code.Code`.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['Code']


class Code(Vendor):
    """PPPoE Active Discovery Code Fields"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/pppoe-parameters/pppoe-parameters-2.csv'
    #: Digits of a value in hex form.
    WIDTH = 2

    def hexlify(self, code: 'int') -> 'str':
        """Convert code to hex form.

        Args:
            code: Field code.

        Returns:
            The code as ``0x`` and :attr:`WIDTH` upper-case hex digits.

        """
        return f'0x{code:0{self.WIDTH}X}'

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: CSV data.

        Returns:
            Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: self.safe_name(item[1]),
                                       filter(lambda item: '-' not in item[0], reader)))

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
            name = item[1]
            rfcs = item[3]

            temp = []  # type: list[str]
            for rfc in self.split_references(rfcs):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', '%s %s' % (  # pylint: disable=consider-using-f-string
                name, ''.join(temp) if rfcs else '',
            ), flags=re.MULTILINE))

            # NOTE: IANA writes a value as ``7 (0x07)``, or bare where it is unassigned,
            # and a range as ``1-6``, all in decimal.
            value = item[0].split(' ', maxsplit=1)[0]
            if '-' in value:
                start, stop = map(int, value.split('-'))

                miss.append(f'if {self.hexlify(start)} <= value <= {self.hexlify(stop)}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(name)}')")
                continue

            code = self.hexlify(int(value))
            renm = self.rename(name, code)

            pres = f'{renm} = {code}'
            sufs = f'#: {desc}'

            enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(Code())  # type: ignore[arg-type]
