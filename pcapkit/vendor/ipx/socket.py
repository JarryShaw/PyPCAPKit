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

NAME = 'Socket'
DOCS = 'Socket Types'
FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
LINK = 'https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#Socket_number'

###############
# Processors
###############

# page = requests.get(LINK)
# soup = bs4.BeautifulSoup(page.text, 'html5lib')
with tempfile.TemporaryDirectory(prefix='{}/'.format(os.path.realpath(os.curdir))) as tempdir:
    index_html = os.path.join(tempdir, 'index.html')

    webbrowser.open(LINK)
    print('Please save the HTML code as {!r}.'.format(index_html))
    input('Press ENTER to continue...')

    with open(index_html) as file:
        text = file.read()
soup = bs4.BeautifulSoup(text, 'html5lib')

table = soup.find_all('table', class_='wikitable')[3]
content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)  # pylint: disable=filter-builtin-not-iterating
header = next(content)

enum = list()
miss = list()
for item in content:
    line = item.find_all('td')

    pval = ' '.join(line[0].stripped_strings)
    dscp = ' '.join(line[1].stripped_strings)

    data = list(filter(None, map(lambda s: s.strip(),
                                 re.split(r'\W*,|\(|\)\W*', dscp))))
    if len(data) == 2:
        name, desc = data
    else:
        name, desc = dscp, ''

    try:
        code, _ = pval, int(pval, base=16)

        pres = "{}[{!r}] = {}".format(NAME, name, code).ljust(76)
        sufs = '# {}'.format(desc) if desc else ''

        enum.append('{}{}'.format(pres, sufs))
    except ValueError:
        start, stop = pval.split('-')

        miss.append('if {} <= value <= {}:'.format(start, stop))
        if desc:
            miss.append('    # {}'.format(desc))
        miss.append(
            "    extend_enum(cls, '{} [0x%s]' % hex(value)[2:].upper().zfill(4), value)".format(name))
        miss.append('    return cls(value)')

###############
# Defaults
###############

temp, FILE = os.path.split(os.path.abspath(__file__))
ROOT, STEM = os.path.split(temp)

ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))


LINE = lambda NAME, DOCS, FLAG, ENUM, MISS: '''\
# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class {}(IntEnum):
    """Enumeration class for {}."""
    _ignore_ = '{} _'
    {} = vars()

    # {}
    {}

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return {}(key)
        if key not in {}._member_map_:
            extend_enum({}, key, default)
        return {}[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not ({}):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        {}
        super()._missing_(value)
'''.format(NAME, NAME, NAME, NAME, DOCS, ENUM, NAME, NAME, NAME, NAME, FLAG, MISS)


with contextlib.suppress(FileExistsError):
    os.mkdir(os.path.join(ROOT, '../const/{}'.format(STEM)))
with open(os.path.join(ROOT, '../const/{}/{}'.format(STEM, FILE)), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
