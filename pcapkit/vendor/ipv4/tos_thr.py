# -*- coding: utf-8 -*-

import collections
import contextlib
import os

###############
# Macros
###############

NAME = 'TOS_THR'
DOCS = 'TOS (DS Field) Throughput'
FLAG = 'isinstance(value, int) and 0 <= value <= 1'
DATA = {
    0: 'Normal',
    1: 'High',
}

###############
# Processors
###############

record = collections.Counter(DATA.values())


def rename(name, code):
    if record[name] > 1:
        name = '{} [{}]'.format(name, code)
    return name


enum = list()
miss = [
    "extend_enum(cls, 'Unassigned [%d]' % value, value)",
    'return cls(value)'
]
for code, name in DATA.items():
    renm = rename(name, code).upper()
    enum.append("{}[{!r}] = {}".format(NAME, renm, code).ljust(76))

###############
# Defaults
###############

temp, FILE = os.path.split(os.path.abspath(__file__))
ROOT, STEM = os.path.split(temp)

ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))


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
        super()._missing_(value)
'''.format(NAME, NAME, NAME, NAME, DOCS, ENUM, NAME, NAME, NAME, NAME, FLAG, MISS)


with contextlib.suppress(FileExistsError):
    os.mkdir(os.path.join(ROOT, '../const/{}'.format(STEM)))
with open(os.path.join(ROOT, '../const/{}/{}'.format(STEM, FILE)), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
