# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position

###############################################################################
import sys
sys.path.pop(0)  # noqa
###############################################################################

import contextlib
import os
import re
import webbrowser
import tempfile

import bs4
# import requests

###############
# Macros
###############

NAME = 'Packet'
DOCS = 'IPX Packet Types'
FLAG = 'isinstance(value, int) and 0 <= value <= 255'
LINK = 'https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#IPX_packet_structure'

###############
# Processors
###############

# page = requests.get(LINK)
# soup = bs4.BeautifulSoup(page.text, 'html5lib')
with tempfile.TemporaryDirectory(prefix=f'{os.path.realpath(os.curdir)}/') as tempdir:
    index_html = os.path.join(tempdir, 'index.html')

    webbrowser.open(LINK)
    print(f'Please save the HTML code as {index_html!r}.')
    input('Press ENTER to continue...')

    with open(index_html) as file:
        text = file.read()
soup = bs4.BeautifulSoup(text, 'html5lib')

table = soup.find_all('table', class_='wikitable')[1]
content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)  # pylint: disable=filter-builtin-not-iterating
header = next(content)

enum = list()
miss = [
    "extend_enum(cls, 'Unassigned [%d]' % value, value)",
    'return cls(value)'
]
for item in content:
    line = item.find_all('td')

    pval = ''.join(line[0].stripped_strings)
    desc = ''.join(line[1].stripped_strings)

    split = desc.split(' (', 1)
    if len(split) == 2:
        name = split[0]
        cmmt = re.sub(
            r'(RFC \d+)', r'[\1]', re.sub(r',([^ ])', r', \1', split[1].replace(')', '', 1)))
    else:
        name, cmmt = desc, ''

    pres = f"{NAME}[{name!r}] = {pval}".ljust(76)
    sufs = f'# {cmmt}' if cmmt else ''

    enum.append(f'{pres}{sufs}')

###############
# Defaults
###############

temp, FILE = os.path.split(os.path.abspath(__file__))
ROOT, STEM = os.path.split(temp)

ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))


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


with contextlib.suppress(FileExistsError):
    os.mkdir(os.path.join(ROOT, f'../const/{STEM}'))
with open(os.path.join(ROOT, f'../const/{STEM}/{FILE}'), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
