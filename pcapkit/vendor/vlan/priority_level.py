# -*- coding: utf-8 -*-
"""Priority levels defined in IEEE 802.1p
============================================

.. module:: pcapkit.vendor.vlan.priority_level

This module contains the vendor crawler for **Priority levels defined in IEEE 802.1p**,
which is automatically generating :class:`pcapkit.const.vlan.priority_level.PriorityLevel`.

"""

import collections
import re
import sys
from typing import TYPE_CHECKING

import bs4

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

    from bs4 import BeautifulSoup

__all__ = ['PriorityLevel']


class PriorityLevel(Vendor):
    """Priority levels defined in IEEE 802.1p"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b000 <= value <= 0b111'
    #: Link to registry.
    LINK = 'https://en.wikipedia.org/wiki/IEEE_P802.1p#Priority_levels'

    def request(self, text: 'str') -> 'BeautifulSoup':  # type: ignore[override] # pylint: disable=signature-differs,arguments-renamed
        """Fetch registry table.

        Args:
            text: Context from :attr:`~LinkType.LINK`.

        Returns:
            Parsed HTML source.

        """
        return bs4.BeautifulSoup(text, 'html5lib')

    def count(self, soup: 'BeautifulSoup') -> 'Counter[str]':  # pylint: disable=signature-differs,arguments-renamed,unused-argument
        """Count field records."""
        return collections.Counter()

    def process(self, soup: 'BeautifulSoup') -> 'tuple[list[str], list[str]]':  # pylint: disable=arguments-differ,arguments-renamed,unused-argument
        """Process HTML data.

        Args:
            data: Parsed HTML source.

        Returns:
            Enumeration fields and missing fields.

        """
        table = soup.find_all('table', class_='wikitable')[0]
        content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)
        next(content)  # header

        enum = []  # type: list[str]
        miss = [
            "return extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(3), value)",
        ]
        for item in content:
            line = item.find_all('td')

            pval = ' '.join(line[0].stripped_strings)
            prio = ' '.join(line[1].stripped_strings)
            abbr = ' '.join(line[2].stripped_strings)
            desc = ' '.join(line[3].stripped_strings)

            match = re.match(r'(\d) *(\(.*\))*', prio)
            group = match.groups()  # type: ignore[union-attr]

            code = f'0b{bin(int(pval))[2:].zfill(3)}'
            tmp1 = self.wrap_comment(f"{desc} {group[1] or ''}")

            pres = f"{abbr} = {code}"
            sufs = f"#: {tmp1}"

            # if len(pres) > 74:
            #     sufs = f"\n{' '*80}{sufs}"

            # enum.append(f'{pres.ljust(76)}{sufs}')
            enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(PriorityLevel())  # type: ignore[arg-type]
