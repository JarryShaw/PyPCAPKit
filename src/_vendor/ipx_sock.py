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
        super()._missing_(value)
'''


###############
# Macros
###############

NAME = 'Sockets'
DOCS = 'Socket Types'
FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
LINK = 'https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#Socket_number'


###############
# Processors
###############


page = requests.get(LINK)
soup = bs4.BeautifulSoup(page.text, 'html5lib')

table = soup.find_all('table', class_='wikitable')[3]
content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)
header = next(content)

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

    try:
        code, _ = pval, int(pval, base=16)

        pres = f"{NAME}[{name!r}] = {code}".ljust(76)
        sufs = f'# {desc}' if desc else ''

        enum.append(f'{pres}{sufs}')
    except ValueError:
        start, stop = pval.split('-')

        miss.append(f'if {start} <= value <= {stop}:')
        if desc:
            miss.append(f'    # {desc}')
        miss.append(f"    extend_enum(cls, '{name} [0x%s]' % hex(value)[2:].upper().zfill(4), value)")
        miss.append('    return cls(value)')


###############
# Defaults
###############


ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))
with open(os.path.join(ROOT, f'../_common/{FILE}'), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
