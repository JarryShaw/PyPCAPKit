# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position
"""IPX Packet Types
======================

.. module:: pcapkit.vendor.ipx.packet

This module contains the vendor crawler for **IPX Packet Types**,
which is automatically generating :class:`pcapkit.const.ipx.packet.Packet`.

"""

###############################################################################
# NOTE: fix duplicated name of ``socket```
import sys

path = sys.path.pop(0)
###############################################################################

import collections
import re
from typing import TYPE_CHECKING

import bs4

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

    from bs4 import BeautifulSoup

###############################################################################
sys.path.insert(0, path)
###############################################################################

__all__ = ['Packet']


class Packet(Vendor):
    """IPX Packet Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#IPX_packet_structure'

    def count(self, data: 'BeautifulSoup') -> 'Counter[str]':
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter()

    def request(self, text: 'str') -> 'BeautifulSoup':  # type: ignore[override] # pylint: disable=signature-differs
        """Fetch HTML source.

        Args:
            text: Context from :attr:`~Vendor.LINK`.

        Returns:
            Parsed HTML source.

        """
        return bs4.BeautifulSoup(text, 'html5lib')

    def process(self, soup: 'BeautifulSoup') -> 'tuple[list[str], list[str]]':  # pylint: disable=arguments-differ,arguments-renamed
        """Process HTML source.

        Args:
            data: Parsed HTML source.

        Returns:
            Enumeration fields and missing fields.

        """
        table = soup.find_all('table', class_='wikitable')[1]
        content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)
        next(content)  # header

        enum = []  # type: list[str]
        miss = [
            "return extend_enum(cls, 'Unassigned_%d' % value, value)",
        ]
        for item in content:
            line = item.find_all('td')

            pval = ''.join(line[0].stripped_strings)
            desc = ''.join(line[1].stripped_strings)

            split = desc.split(' (', 1)
            if len(split) == 2:
                name = split[0]
                cmmt = re.sub(r'RFC (\d+)', r'[:rfc:`\1`]', re.sub(r',([^ ])', r', \1', split[1].replace(')', '', 1)))
            else:
                name, cmmt = desc, ''
            renm = self.safe_name(name)

            if cmmt:
                name = f'``{name}``'
                tmp1 = f', {cmmt}'
            else:
                tmp1 = ''
            desc = self.wrap_comment(f'{name}{tmp1}')

            pres = f"{renm} = {pval}"
            sufs = f'#: {desc}'

            # if len(pres) > 74:
            #     sufs = f"\n{' '*80}{sufs}"

            # enum.append(f'{pres.ljust(76)}{sufs}')
            enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(Packet())  # type: ignore[arg-type]
