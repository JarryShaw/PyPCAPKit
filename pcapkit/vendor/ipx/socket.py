# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position
"""Socket Types
==================

.. module:: pcapkit.vendor.ipx.socket

This module contains the vendor crawler for **Socket Types**,
which is automatically generating :class:`pcapkit.const.ipx.socket.Socket`.

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

__all__ = ['Socket']


class Socket(Vendor):
    """Socket Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#Socket_number'

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
        table = soup.find_all('table', class_='wikitable')[3]
        content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)
        next(content)  # header

        enum = []  # type: list[str]
        miss = []  # type: list[str]
        for item in content:
            line = item.find_all('td')

            pval = ' '.join(line[0].stripped_strings)
            dscp = ' '.join(line[1].stripped_strings)

            data = list(filter(None, map(lambda s: s.strip(), re.split(r'\W*,|\(|\)\W*', dscp))))
            if len(data) == 2:
                name, desc = data
            else:
                name, desc = dscp, ''
            renm = self.safe_name(name)

            tmp1 = f', {desc}' if desc else ''
            desc = self.wrap_comment(f'{name}{tmp1}')

            try:
                code, _ = pval, int(pval, base=16)

                pres = f"{renm} = {code}"
                sufs = f'#: {desc}'

                # if len(pres) > 74:
                #     sufs = f"\n{' '*80}{sufs}"

                # enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = pval.split('–')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return extend_enum(cls, '{name}_0x%s' % hex(value)[2:].upper().zfill(4), value)")
        return enum, miss


if __name__ == '__main__':
    sys.exit(Socket())  # type: ignore[arg-type]
