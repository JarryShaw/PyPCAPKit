# -*- coding: utf-8 -*-
"""Option Types
==================

.. module:: pcapkit.vendor.pcapng.option_type

This module contains the vendor crawler for **Option Types**,
which is automatically generating :class:`pcapkit.const.pcapng.option_type.OptionType`.

"""

import collections
import sys
from typing import TYPE_CHECKING

import bs4

from pcapkit.vendor.default import Vendor

__all__ = ['OptionType']

if TYPE_CHECKING:
    from collections import Counter

    from bs4.element import Tag


class OptionType(Vendor):
    """Option Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html'

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records."""
        return collections.Counter()

    def request(self, text: 'str') -> 'dict[str, list[Tag]]':  # type: ignore[override] # pylint: disable=signature-differs
        """Fetch registry table.

        Args:
            text: Context from :attr:`~LinkType.LINK`.

        Returns:
            Rows (``tr``) from registry table (``table``).

        """
        soup = bs4.BeautifulSoup(text, 'html5lib')
        table_1 = soup.select('table#table-1')[0]
        table_3 = soup.select('table#table-3')[0]
        table_4 = soup.select('table#table-4')[0]
        table_7 = soup.select('table#table-7')[0]
        return {
            'table-1': table_1.select('tr')[1:],
            'table-3': table_3.select('tr')[1:],
            'table-4': table_4.select('tr')[1:],
            'table-7': table_7.select('tr')[1:],
        }

    def process(self, data: 'dict[str, list[Tag]]') -> 'tuple[list[str], list[str]]':  # type: ignore[override]
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = []  # type: list[str]

        for content in data['table-1']:
            name = content.select('td')[0].text.strip()
            temp = content.select('td')[1].text.strip()

            try:
                code = int(temp)

                pref = f'{name} = {code}'
                sufs = self.wrap_comment(name)

                enum.append(f'#: {sufs}\n    {pref}')
            except ValueError:
                opts = tuple(map(lambda x: int(x), temp.split('/')))

                miss.append(f'if value in {opts!r}:')
                miss.append(f'    #: {name}')
                miss.append(f"    extend_enum(cls, '{self.safe_name(name)}_%d' % value, value)")
                miss.append('    return cls(value)')

        for content in data['table-3']:
            name = content.select('td')[0].text.strip()
            code = content.select('td')[1].text.strip()

            pref = f'{name} = {int(code)}'
            sufs = self.wrap_comment(name)

            enum.append(f'#: {sufs}\n    {pref}')

        for content in data['table-4']:
            name = content.select('td')[0].text.strip()
            code = content.select('td')[1].text.strip()

            pref = f'{name} = {int(code)}'
            sufs = self.wrap_comment(name)

            enum.append(f'#: {sufs}\n    {pref}')

        for content in data['table-7']:
            name = content.select('td')[0].text.strip()
            code = content.select('td')[1].text.strip()

            pref = f'{name} = {int(code)}'
            sufs = self.wrap_comment(name)

            enum.append(f'#: {sufs}\n    {pref}')

        return enum, miss


if __name__ == '__main__':
    sys.exit(OptionType())  # type: ignore[arg-type]
