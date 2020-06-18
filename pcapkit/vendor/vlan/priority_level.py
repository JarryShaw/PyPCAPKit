# -*- coding: utf-8 -*-
"""VLAN priority levels defined in IEEE 802.1p."""

import re

import bs4

from pcapkit.vendor.default import Vendor

__all__ = ['PriorityLevel']


class PriorityLevel(Vendor):
    """Priority levels defined in IEEE 802.1p."""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b000 <= value <= 0b111'
    #: Link to registry.
    LINK = 'https://en.wikipedia.org/wiki/IEEE_P802.1p#Priority_levels'

    def request(self, text):  # pylint: disable=signature-differs
        """Fetch CSV file.

        Args:
            text (str): Context from :attr:`~PriorityLevel.LINK`.

        Returns:
            bs4.BeautifulSoup: Parsed HTML source.

        """
        return bs4.BeautifulSoup(text, 'html5lib')

    def count(self, soup):  # pylint: disable=arguments-differ
        """Count field records."""

    def process(self, soup):  # pylint: disable=arguments-differ
        """Process HTML data.

        Args:
            data (bs4.BeautifulSoup): Parsed HTML source.

        Returns:
            List[str]: Enumeration fields.
            List[str]: Missing fields.

        """
        table = soup.find_all('table', class_='wikitable')[0]
        content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)  # pylint: disable=filter-builtin-not-iterating
        next(content)  # header

        enum = list()
        miss = [
            "extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(3), value)",
            'return cls(value)'
        ]
        for item in content:
            line = item.find_all('td')

            pval = ' '.join(line[0].stripped_strings)
            prio = ' '.join(line[1].stripped_strings)
            abbr = ' '.join(line[2].stripped_strings)
            desc = ' '.join(line[3].stripped_strings)

            match = re.match(r'(\d) *(\(.*\))*', prio)
            group = match.groups()

            code = f'0b{bin(int(pval))[2:].zfill(3)}'
            tmp1 = self.wrap_comment(f"``{group[0]}`` - {desc} {group[1] or ''}")

            pres = f"{abbr} = {code}"
            sufs = f"#: {tmp1}"

            # if len(pres) > 74:
            #     sufs = f"\n{' '*80}{sufs}"

            # enum.append(f'{pres.ljust(76)}{sufs}')
            enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == "__main__":
    PriorityLevel()
