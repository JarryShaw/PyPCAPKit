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


NAME = 'Options'
DOCS = 'IP Option Numbers'
FLAG = 'isinstance(value, int) and 0 <= value <= 255'
LINK = 'https://www.iana.org/assignments/ip-parameters/ip-parameters-1.csv'


###############
# Processors
###############


page = requests.get(LINK)
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)
record = collections.Counter(map(lambda item: item[4],
                                 filter(lambda item: len(item[3].split('-')) != 2, reader)))


def rename(name, code, *, original):
    if record[original] > 1:
        return '{} [{}]'.format(name, code)
    return name


reader = csv.reader(data)
header = next(reader)

enum = list()
miss = [
    "extend_enum(cls, 'Unassigned [%d]' % value, value)",
    'return cls(value)'
]
for item in reader:
    code = item[3]
    dscp = item[4]
    rfcs = item[5]

    temp = list()
    for rfc in filter(None, re.split(r'\[|\]', rfcs)):
        if re.match(r'\d+', rfc):
            continue
        if 'RFC' in rfc:
            temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
        else:
            temp.append('[{}]'.format(rfc))
    desc = " {}".format(''.join(temp)) if rfcs else ''

    abbr, name = re.split(r'\W+-\W+', dscp)
    temp = re.sub(r'\[\d+\]', '', name)
    name = ' {}'.format(temp) if temp else ''

    renm = rename(abbr or 'Unassigned [{}]'.format(code), code, original=dscp)
    pres = "{}[{!r}] = {}".format(NAME, renm, code).ljust(76)
    sufs = '#{}{}'.format(desc, name) if desc or name else ''

    enum.append('{}{}'.format(pres, sufs))


###############
# Defaults
###############


ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))
with open(os.path.join(ROOT, '../_common/{}'.format(FILE)), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
