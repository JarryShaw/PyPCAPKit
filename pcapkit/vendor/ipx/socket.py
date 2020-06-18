# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position
"""IPX Socket Types"""

###############################################################################
# NOTE: fix duplicated name of ``socket```
import sys
path = sys.path.pop(0)
###############################################################################

import re

import bs4

from pcapkit.vendor.default import Vendor

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

    def count(self, data):
        """Count field records."""

    def request(self, text):  # pylint: disable=signature-differs
        """Fetch HTML source.

        Args:
            text (str): Context from :attr:`~Vendor.LINK`.

        Returns:
            bs4.BeautifulSoup: Parsed HTML source.

        """
        return bs4.BeautifulSoup(text, 'html5lib')

    def process(self, soup):  # pylint: disable=arguments-differ
        """Process HTML source.

        Args:
            data (bs4.BeautifulSoup): Parsed HTML source.

        Returns:
            List[str]: Enumeration fields.
            List[str]: Missing fields.

        """
        table = soup.find_all('table', class_='wikitable')[3]
        content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)  # pylint: disable=filter-builtin-not-iterating
        next(content)  # header

        enum = list()
        miss = list()
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

            tmp1 = f' - {desc}' if desc else ''
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
                miss.append(f"    extend_enum(cls, '{name}_0x%s' % hex(value)[2:].upper().zfill(4), value)")
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Socket()
