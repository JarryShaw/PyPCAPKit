# -*- coding: utf-8 -*-

import collections
import contextlib
import os
import re

import bs4
import requests

###############
# Macros
###############

NAME = 'ReturnCode'
DOCS = 'FTP Server Return Code'
FLAG = 'isinstance(value, int) and 100 <= value <= 659'
LINK = 'https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes'

###############
# Processors
###############

page = requests.get(LINK)
soup = bs4.BeautifulSoup(page.text, 'html5lib')

table = soup.find_all('table', class_='wikitable')[2]
content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)
header = next(content)

temp = list()
for item in content:
    line = item.find_all('td')

    code = ' '.join(line[0].stripped_strings)
    if len(code) != 3:
        continue
    desc = f"{' '.join(line[1].stripped_strings).split('.')[0].strip()}."
    temp.append(desc)
record = collections.Counter(temp)


def rename(name, code):
    if record[name] > 1:
        name = f'{name} [{code}]'
    return name


table = soup.find_all('table', class_='wikitable')[2]
content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)
header = next(content)

enum = list()
for item in content:
    line = item.find_all('td')

    code = ' '.join(line[0].stripped_strings)
    if len(code) != 3:
        continue
    desc = f"{' '.join(line[1].stripped_strings).split('.')[0].strip()}."
    enum.append(f'{NAME}[{rename(desc, code)!r}] = {code}')

###############
# Defaults
###############

temp, FILE = os.path.split(os.path.abspath(__file__))
ROOT, STEM = os.path.split(temp)

ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))


def LINE(NAME, DOCS, FLAG, ENUM): return f'''\
# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum

KIND = {{
    '1': 'Positive Preliminary',
    '2': 'Positive Completion',
    '3': 'Positive Intermediate',
    '4': 'Transient Negative Completion',
    '5': 'Permanent Negative Completion',
    '6': 'Protected',
}}

INFO = {{
    '0': 'Syntax',
    '1': 'Information',
    '2': 'Connections',
    '3': 'Authentication and accounting',
    '4': 'Unspecified',                     # [RFC 959]
    '5': 'File system',
}}


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
        code = str(value)
        kind = KIND.get(code[0], 'Reserved')
        info = INFO.get(code[1], 'Reserved')
        extend_enum(cls, '%s - %s [%s]' % (kind, info, value), value)
        return cls(value)
'''


with contextlib.suppress(FileExistsError):
    os.mkdir(os.path.join(ROOT, f'../const/{STEM}'))
with open(os.path.join(ROOT, f'../const/{STEM}/{FILE}'), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM))
