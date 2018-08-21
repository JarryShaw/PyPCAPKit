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
        super()._missing_(value)
'''


###############
# Macros
###############


NAME = 'RT_ALT'
DOCS = 'IPv4 Router Alert Option Values'
FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
LINK = 'https://www.iana.org/assignments/ip-parameters/ipv4-router-alert-option-values.csv'


###############
# Processors
###############


page = requests.get(LINK)
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)
record = collections.Counter(map(lambda item: item[1],
    filter(lambda item: len(item[0].split('-')) != 2, reader)))

def rename(name, code):
    if record[name] > 1:
        return f'{name} [{code}]'
    return name

reader = csv.reader(data)
header = next(reader)

enum = list()
miss = list()
for item in reader:
    name = item[1]
    rfcs = item[2]

    temp = list()
    for rfc in filter(None, re.split(r'\[|\]', rfcs)):
        if 'RFC' in rfc:
            temp.append(f'[{rfc[:3]} {rfc[3:]}]')
        else:
            temp.append(f'[{rfc}]')
    desc = f"# {''.join(temp)}" if rfcs else ''

    try:
        code, _ = item[0], int(item[0])
        renm = rename(name, code)

        pres = f"{NAME}[{renm!r}] = {code}".ljust(76)
        sufs = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

        enum.append(f'{pres}{sufs}')
    except ValueError:
        start, stop = map(int, item[0].split('-'))
        more = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

        if 'Level' in name:
            base = name.rstrip('s 0-31')
            for code in range(start, stop+1):
                renm = f'{base} {code-start}'
                pres = f"{NAME}[{renm!r}] = {code}".ljust(76)

                enum.append(f'{pres}{more}')
        else:
            miss.append(f'if {start} <= value <= {stop}:')
            if more:
                miss.append(f'    {more}')
            miss.append(f"    extend_enum(cls, '{name} [%d]' % value, value)")
            miss.append('    return cls(value)')


###############
# Defaults
###############


ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))
with open(os.path.join(ROOT, f'../_common/{FILE}'), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
