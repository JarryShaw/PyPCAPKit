# -*- coding: utf-8 -*-
"""IPv6 Neighbor Discovery Option Formats
============================================

.. module:: pcapkit.vendor.icmpv6.nd_option

This module contains the vendor crawler for **IPv6 Neighbor Discovery
Option Formats**, which is automatically generating
:class:`pcapkit.const.icmpv6.nd_option.NDOption`.

.. versionadded:: 1.9.0

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['NDOption']


class NDOption(Vendor):
    """IPv6 Neighbor Discovery Option Formats [:rfc:`4861`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters-5.csv'

    @staticmethod
    def _name(cell: 'str') -> 'str':
        """Normalise a description cell into the name it gives.

        IANA wraps one description across two lines and marks the RFC 3692
        experiments with a footnote, ``[1]``; neither is part of the name.

        Args:
            cell: Description cell.

        Returns:
            The name, its whitespace collapsed and its footnote dropped.

        """
        return re.sub(r'\s*\[\d+\]$', '', ' '.join(cell.split()))

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: CSV data.

        Returns:
            Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(self.safe_name(self._name(item[1]))
                                   for item in reader if len(item[0].split('-')) != 2)

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
            name = self._name(item[1])
            rfcs = item[2]

            temp = []  # type: list[str]
            for rfc in self.split_references(rfcs):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''
            desc = self.wrap_comment(f'{name}{tmp1}')

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code)

                pres = f"{renm} = {code}"
                sufs = f'#: {desc}'

                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(name)}')")
        miss.append("return cls._unregistered_member(value, 'Unassigned')")
        return enum, miss


if __name__ == '__main__':
    sys.exit(NDOption())  # type: ignore[arg-type]
