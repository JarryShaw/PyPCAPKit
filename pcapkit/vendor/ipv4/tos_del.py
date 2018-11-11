# -*- coding: utf-8 -*-

import collections
import contextlib
import os

###############
# Macros
###############

NAME = 'TOS_DEL'
DOCS = 'TOS (DS Field) Delay'
FLAG = 'isinstance(value, int) and 0 <= value <= 1'
DATA = {
    0: 'Normal',
    1: 'Low',
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
    "extend_enum(cls, 'Unassigned [%d]' % value, value)",
    'return cls(value)'
]
for code, name in DATA.items():
    renm = rename(name, code).upper()
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
