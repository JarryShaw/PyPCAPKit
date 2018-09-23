# -*- coding: utf-8 -*-

import collections
import os

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


NAME = 'SeedID'
DOCS = 'Seed-ID Types'
FLAG = 'isinstance(value, int) and 0b00 <= value <= 0b11'
DATA = {
    0b00: 'IPv6 Source Address',                   # [RFC 7731]
    0b01: '16-Bit Unsigned Integer',               # [RFC 7731]
    0b10: '64-Bit Unsigned Integer',               # [RFC 7731]
    0b11: '128-Bit Unsigned Integer',              # [RFC 7731]
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
    "extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(2), value)",
    'return cls(value)'
]
for code, name in DATA.items():
    code = '0b{}'.format(bin(code)[2:].zfill(2))
    renm = rename(name, code).upper()
    enum.append("{}[{!r}] = {}".format(NAME, renm, code).ljust(76))


###############
# Defaults
###############


ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))
with open(os.path.join(ROOT, '../_common/{}'.format(FILE)), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
