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
        super()._missing_(value)
'''.format(NAME, NAME, NAME, NAME, DOCS, ENUM, NAME, NAME, NAME, NAME, FLAG, MISS)


###############
# Macros
###############


NAME = 'EtherType'
DOCS = 'Ethertype IEEE 802 Numbers'
FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
LINK = 'https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers-1.csv'


###############
# Processors
###############


page = requests.get(LINK)
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)
record = collections.Counter(map(lambda item: item[4],
                                 filter(lambda item: len(item[1].split('-')) != 2, reader)))


def rename(name, code):
    if record[name] > 1:
        name = '{} [0x{}]'.format(name, code)
    return name


reader = csv.reader(data)
header = next(reader)

enum = list()
miss = list()
for item in reader:
    name = item[4]
    rfcs = item[5]

    temp = list()
    for rfc in filter(None, re.split(r'\[|\]', rfcs)):
        if 'RFC' in rfc:
            temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
        else:
            temp.append('[{}]'.format(rfc))
    desc = re.sub(r'( )( )*', ' ',
                  "# {}".format(''.join(temp)).replace('\n', ' ')) if rfcs else ''

    try:
        code, _ = item[1], int(item[1], base=16)
        renm = re.sub(r'( )( )*', ' ', rename(name, code).replace('\n', ' '))

        pres = "{}[{!r}] = 0x{}".format(NAME, renm, code).ljust(76)
        sufs = "\n{}{}".format(' '*80, desc) if len(pres) >= 80 else desc

        enum.append('{}{}'.format(pres, sufs))
    except ValueError:
        start, stop = item[1].split('-')
        more = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

        miss.append('if 0x{} <= value <= 0x{}:'.format(start, stop))
        if more:
            miss.append('    {}'.format(more))
        miss.append(
            "    extend_enum(cls, '{} [0x%s]' % hex(value)[2:].upper().zfill(4), value)".format(name))
        miss.append('    return cls(value)')


###############
# Defaults
###############


ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))
with open(os.path.join(ROOT, '../_common/{}'.format(FILE)), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
