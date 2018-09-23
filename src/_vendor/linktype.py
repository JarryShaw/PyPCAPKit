# -*- coding: utf-8 -*-

import os
import re

import requests

###############
# Defaults
###############


ROOT, FILE = os.path.split(os.path.abspath(__file__))


def LINE(NAME, DOCS, FLAG, ENUM, MISS): return '''\
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
'''.format(NAME, NAME, NAME, NAME, DOCS, ENUM, NAME, NAME, NAME, NAME, FLAG, MISS)


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

        pres = "{}[{!r}] = {}".format(NAME, name, code).ljust(76)
        sufs = "# {}".format(desc)

        enum.append('{}{}'.format(pres, sufs))
    except ValueError:
        start, stop = map(int, temp.split('-'))
        for code in range(start, stop+1):
            name = 'USER{}'.format(code-start)
            desc = 'DLT_USER{code-start}'

            pres = "{}[{!r}] = {}".format(NAME, name, code).ljust(76)
            sufs = "# {}".format(desc)

            enum.append('{}{}'.format(pres, sufs))


###############
# Defaults
###############


ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))
with open(os.path.join(ROOT, '../_common/{}'.format(FILE)), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
