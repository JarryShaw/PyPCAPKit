# -*- coding: utf-8 -*-

import contextlib
import os
import re

import requests

###############
# Macros
###############

NAME = 'LinkType'
DOCS = 'Link-Layer Header Type Values'
FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF_FFFF'
LINK = 'http://www.tcpdump.org/linktypes.html'

###############
# Processors
###############

page = requests.get(LINK)
table = re.split(r'\<[/]*table.*\>', page.text)[1]
content = re.split(r'\<tr valign=top\>', table)[1:]

enum = list()
miss = [
    "extend_enum(cls, 'Unassigned [%d]' % value, value)",
    'return cls(value)'
]
for content in content:
    item = content.strip().split('<td>')
    name = item[1].strip('</td>')[9:]
    temp = item[2].strip('</td>')
    desc = item[3].strip('</td>')

    try:
        code, _ = temp, int(temp)

        pres = f"{NAME}[{name!r}] = {code}".ljust(76)
        sufs = f"# {desc}"

        enum.append(f'{pres}{sufs}')
    except ValueError:
        start, stop = map(int, temp.split('-'))
        for code in range(start, stop+1):
            name = f'USER{code-start}'
            desc = 'DLT_USER{code-start}'

            pres = f"{NAME}[{name!r}] = {code}".ljust(76)
            sufs = f"# {desc}"

            enum.append(f'{pres}{sufs}')

###############
# Defaults
###############

temp, FILE = os.path.split(os.path.abspath(__file__))
ROOT, STEM = os.path.split(temp)

ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))


def LINE(NAME, DOCS, FLAG, ENUM, MISS): return f'''\
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


with contextlib.suppress(FileExistsError):
    os.mkdir(os.path.join(ROOT, f'../const/{STEM}'))
with open(os.path.join(ROOT, f'../const/{STEM}/{FILE}'), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
