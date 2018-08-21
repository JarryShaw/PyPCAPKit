# -*- coding: utf-8 -*-


import os
import re

import bs4
import requests


###############
# Defaults
###############


ROOT, FILE = os.path.split(os.path.abspath(__file__))

LINE = lambda NAME, DOCS, FLAG, ENUM, MISS: f'''\
# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class {NAME}(IntEnum):
    """Enumeration class for {NAME}."""
    _ignore_ = '{NAME} _'
    {NAME} = vars()

    # {DOCS}
    {ENUM}

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return {NAME}(key)
        if key not in {NAME}._member_map_:
            extend_enum({NAME}, key, default)
        return {NAME}[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not ({FLAG}):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        {MISS}
'''


###############
# Macros
###############


NAME = 'PrioLvl'
DOCS = 'priority levels defined in IEEE 802.1p'
FLAG = 'isinstance(value, int) and 0b000 <= value <= 0b111'
LINK = 'https://en.wikipedia.org/wiki/IEEE_P802.1p#Priority_levels'


###############
# Processors
###############


page = requests.get(LINK)
soup = bs4.BeautifulSoup(page.text, 'html5lib')

table = soup.find_all('table', class_='wikitable')[0]
content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)
header = next(content)

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

    pres = f"{NAME}[{abbr!r}] = {code}".ljust(76)
    sufs = f"# {group[0]} - {desc} {group[1] or ''}"

    enum.append(f'{pres}{sufs}')


###############
# Defaults
###############


ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))
with open(os.path.join(ROOT, f'../_common/{FILE}'), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
