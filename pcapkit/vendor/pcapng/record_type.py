# -*- coding: utf-8 -*-
"""Record Types
==================

.. module:: pcapkit.vendor.pcapng.record_type

This module contains the vendor crawler for **Record Types**,
which is automatically generating :class:`pcapkit.const.pcapng.record_type.RecordType`.

"""

import collections
import sys
from typing import TYPE_CHECKING

import bs4

from pcapkit.vendor.default import Vendor

__all__ = ['RecordType']

if TYPE_CHECKING:
    from collections import Counter

    from bs4.element import Tag


class RecordType(Vendor):
    """Record Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
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
        table_1 = soup.select('table#table-6')[0]
        return table_1.select('tr')[1:]

    def process(self, data: 'list[Tag]') -> 'tuple[list[str], list[str]]':
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = [
            "extend_enum(cls, 'Unassigned_0x%04x' % value, value)",
            'return cls(value)'
        ]
        for content in data:
            name = content.select('td')[0].text.strip()
            temp = content.select('td')[1].text.strip()

            pref = f'{name} = {temp}'
            sufs = self.wrap_comment(name)

            enum.append(f'#: {sufs}\n    {pref}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(RecordType())  # type: ignore[arg-type]
