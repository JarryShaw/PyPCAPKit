# -*- coding: utf-8 -*-
"""VLAN priority levels defined in IEEE 802.1p."""

import re

import bs4

from pcapkit.vendor.default import Vendor

__all__ = ['PriorityLevel']


class PriorityLevel(Vendor):
    """Priority levels defined in IEEE 802.1p."""

    FLAG = 'isinstance(value, int) and 0b000 <= value <= 0b111'
    LINK = 'https://en.wikipedia.org/wiki/IEEE_P802.1p#Priority_levels'

    def request(self, text):  # pylint: disable=signature-differs
        return bs4.BeautifulSoup(text, 'html5lib')

    def count(self, soup):  # pylint: disable=arguments-differ
        pass

    def process(self, soup):  # pylint: disable=arguments-differ
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

            pres = f"{self.NAME}[{abbr!r}] = {code}"
            sufs = f"# {group[0]} - {desc} {group[1] or ''}"

            if len(pres) > 74:
                sufs = f"\n{' '*80}{sufs}"

            enum.append(f'{pres.ljust(76)}{sufs}')
        return enum, miss


if __name__ == "__main__":
    PriorityLevel()
