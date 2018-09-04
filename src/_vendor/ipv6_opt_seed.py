# -*- coding: utf-8 -*-


import collections
import os


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


NAME = 'SeedID'
DOCS = 'Seed-ID Types'
FLAG = 'isinstance(value, int) and 0b00 <= value <= 0b11'
DATA = {
    0b00 : 'IPv6 Source Address',                   # [RFC 7731]
    0b01 : '16-Bit Unsigned Integer',               # [RFC 7731]
    0b10 : '64-Bit Unsigned Integer',               # [RFC 7731]
    0b11 : '128-Bit Unsigned Integer',              # [RFC 7731]
}


###############
# Processors
###############


record = collections.Counter(DATA.values())

def rename(name, code):
    if record[name] > 1:
        name = f'{name} [{code}]'
    return name

enum = list()
miss = [
    "extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(2), value)",
    'return cls(value)'
]
for code, name in DATA.items():
    code = f'0b{bin(code)[2:].zfill(2)}'
    renm = rename(name, code).upper()
    enum.append(f"{NAME}[{renm!r}] = {code}".ljust(76))


###############
# Defaults
###############


ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))
with open(os.path.join(ROOT, f'../_common/{FILE}'), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
