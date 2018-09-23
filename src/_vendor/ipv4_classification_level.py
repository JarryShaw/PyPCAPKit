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


NAME = 'ClasLvl'
DOCS = 'Classification Level Encodings'
FLAG = 'isinstance(value, int) and 0b0000_0000 <= value <= 0b1111_1111'
DATA = {
    0b0000_0001: 'Reserved [4]',
    0b0011_1101: 'Top Secret',
    0b0101_1010: 'Secret',
    0b1001_0110: 'Confidential',
    0b0110_0110: 'Reserved [3]',
    0b1100_1100: 'Reserved [2]',
    0b1010_1011: 'Unclassified',
    0b1111_0001: 'Reserved [1]',
}


###############
# Processors
###############


record = collections.Counter(DATA.values())


def binary(code):
    temp = bin(code)[2:].upper().zfill(8)
    return '0b{}_{}'.format(temp[:4], temp[4:])


def rename(name, code):
    if record[name] > 1:
        name = '{} [{}]'.format(name, code)
    return name


enum = list()
miss = [
    'temp = bin(value)[2:].upper().zfill(8)',
    "extend_enum(cls, 'Unassigned [0b%s]' % (temp[:4]+'_'+temp[4:]), value)",
    'return cls(value)'
]
for code, name in DATA.items():
    code = binary(code)
    renm = rename(name, code)
    enum.append("{}[{!r}] = {}".format(NAME, renm, code).ljust(76))


###############
# Defaults
###############


ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))
with open(os.path.join(ROOT, '../_common/{}'.format(FILE)), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
