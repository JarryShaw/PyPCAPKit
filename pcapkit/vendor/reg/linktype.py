# -*- coding: utf-8 -*-
"""Link-Layer Header Type Values
===================================

.. module:: pcapkit.vendor.reg.linktype

This module contains the vendor crawler for **Link-Layer Header Type Values**,
which is automatically generating :class:`pcapkit.const.reg.linktype.LinkType`.

"""

import collections
import re
import sys
from typing import TYPE_CHECKING

import bs4

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

    from bs4.element import Tag

__all__ = ['LinkType']


class LinkType(Vendor):
    """Link-Layer Header Type Values"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF'
    #: Link to registry.
    LINK = 'http://www.tcpdump.org/linktypes.html'

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records."""
        return collections.Counter()

    def request(self, text: 'str') -> 'list[Tag]':  # type: ignore[override] # pylint: disable=signature-differs
        """Fetch registry table.

        Args:
            text: Context from :attr:`~LinkType.LINK`.

        Returns:
            Rows (``tr``) from registry table (``table``).

        """
        soup = bs4.BeautifulSoup(text, 'html5lib')
        table = soup.select('table.linktypedlt')[0]
        return table.select('tr')[1:]

    def process(self, data: 'list[Tag]') -> 'tuple[list[str], list[str]]':
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = [
            "return extend_enum(cls, 'Unassigned_%d' % value, value)",
        ]
        for content in data:
            name = content.select('td.symbol')[0].text.strip()[9:].strip()
            temp = content.select('td.number')[0].text.strip()
            desc = content.select('td.symbol')[1].text.strip()
            cmmt = re.sub(r'\s+', ' ', content.select('td')[3].text.strip()).replace("''", '``').replace('_', r'\_')

            if not name:
                name = desc[4:]

            try:
                code, _ = temp, int(temp)

                pres = f"{name} = {code}"
                if desc:
                    sufs = "#: %s" % self.wrap_comment(f"[``{desc}``] {cmmt}")  # pylint: disable=consider-using-f-string
                else:
                    sufs = "#: %s" % self.wrap_comment(cmmt)

                # if len(pres) > 74:
                #     sufs = f"\n{' '*80}{sufs}"

                # enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = map(int, temp.split('–'))
                for code in range(start, stop+1):
                    name = f'USER{code-start}'
                    desc = f'DLT_USER{code-start}'

                    pres = f"{name} = {code}"
                    sufs = "#: %s" % self.wrap_comment(f"[``{desc}``] {cmmt}")  # pylint: disable=consider-using-f-string

                    # if len(pres) > 74:
                    #     sufs = f"\n{' '*80}{sufs}"

                    # enum.append(f'{pres.ljust(76)}{sufs}')
                    enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(LinkType())  # type: ignore[arg-type]
