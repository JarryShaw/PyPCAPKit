# -*- coding: utf-8 -*-
"""Block Types
=================

.. module:: pcapkit.vendor.pcapng.block_type

This module contains the vendor crawler for **Block Types**,
which is automatically generating :class:`pcapkit.const.pcapng.block_type.BlockType`.

"""

import collections
import sys
from typing import TYPE_CHECKING

import bs4

from pcapkit.vendor.default import Vendor

__all__ = ['BlockType']

if TYPE_CHECKING:
    from collections import Counter

    from bs4.element import Tag


class BlockType(Vendor):
    """Block Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFFFFFF'
    #: Link to registry.
    LINK = 'https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html'

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
        table = soup.select('table#table-9')[0]
        return table.select('tr')[1:]

    def process(self, data: 'list[Tag]') -> 'tuple[list[str], list[str]]':
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = []  # type: list[str]
        for content in data:
            temp = content.select('td')[0].text.strip()
            desc = ' '.join(content.select('td')[1].stripped_strings)

            if 'Reserved' in desc:
                name = 'Reserved'
            else:
                name = self.safe_name(desc.split('.', maxsplit=1)[0].split('(', maxsplit=1)[0].strip())

            try:
                code = int(temp, base=16)
                if name == 'Reserved':
                    name = f'Reserved_0x{code:08x}'

                pref = f'{name} = 0x{code:08x}'
                sufs = self.wrap_comment(desc)

                enum.append(f'#: {sufs}\n    {pref}')
            except ValueError:
                start, stop = map(lambda x: int(x, base=16), temp.split('-'))

                miss.append(f'if 0x{start:08x} <= value <= 0x{stop:08x}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return extend_enum(cls, '{self.safe_name(name)}_%08x' % value, value)")
        return enum, miss


if __name__ == '__main__':
    sys.exit(BlockType())  # type: ignore[arg-type]
