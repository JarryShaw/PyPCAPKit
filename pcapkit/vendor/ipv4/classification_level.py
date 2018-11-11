# -*- coding: utf-8 -*-

import collections
import contextlib
import os

###############
# Macros
###############

NAME = 'ClassificationLevel'
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
    return f'0b{temp[:4]}_{temp[4:]}'


def rename(name, code):
    if record[name] > 1:
        name = f'{name} [{code}]'
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
    enum.append(f"{NAME}[{renm!r}] = {code}".ljust(76))

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
