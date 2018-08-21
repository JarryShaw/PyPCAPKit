# -*- coding: utf-8 -*-


import collections
import csv
import os
import re

import requests


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


NAME = 'PktType'
DOCS = 'Mobility Header Types - for the MH Type field in the Mobility Header'
FLAG = 'isinstance(value, int) and 0 <= value <= 255'
LINK = 'https://www.iana.org/assignments/mobility-parameters/mobility-parameters-1.csv'


###############
# Processors
###############


page = requests.get(LINK)
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)
record = collections.Counter(map(lambda item: item[1],
    filter(lambda item: len(item[0].split('-')) != 2, reader)))

def rename(name, code, *, original):
    if record[original] > 1:
        return f'{name} [{code}]'
    return name

reader = csv.reader(data)
header = next(reader)

enum = list()
miss = [
    "extend_enum(cls, 'Unassigned [%d]' % value, value)",
    'return cls(value)'
]
for item in reader:
    long = item[1]
    rfcs = item[2]

    temp = list()
    for rfc in filter(None, re.split(r'\[|\]', rfcs)):
        if 'RFC' in rfc:
            temp.append(f'[{rfc[:3]} {rfc[3:]}]')
        else:
            temp.append(f'[{rfc}]')
    desc = f" {''.join(temp)}" if rfcs else ''

    split = long.split(' (', 1)
    if len(split) == 2:
        name = split[0]
        cmmt = f" ({split[1]}"
    else:
        name, cmmt = long, ''

    code, _ = item[0], int(item[0])
    renm = rename(name, code, original=long)

    pres = f"{NAME}[{renm!r}] = {code}".ljust(76)
    sufs = f'# {desc}{cmmt}' if desc or cmmt else ''

    enum.append(f'{pres}{sufs}')


###############
# Defaults
###############


ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))
with open(os.path.join(ROOT, f'../_common/{FILE}'), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
