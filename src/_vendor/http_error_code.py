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


NAME = 'ErrCode'
DOCS = 'HTTP/2 Error Code'
FLAG = 'isinstance(value, int) and 0x0000_0000 <= value <= 0xFFFF_FFFF'
LINK = 'https://www.iana.org/assignments/http2-parameters/error-code.csv'


###############
# Processors
###############


page = requests.get(LINK)
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)
record = collections.Counter(map(lambda item: item[1],
                                 filter(lambda item: len(item[0].split('-')) != 2, reader)))


def hexlify(code):
    temp = hex(code)[2:].upper().zfill(8)
    return '0x{}_{}'.format(temp[:4], temp[4:])


def rename(name, code):
    if record[name] > 1:
        return '{} [{}]'.format(name, code)
    return name


reader = csv.reader(data)
header = next(reader)

enum = list()
miss = list()
for item in reader:
    name = item[1]
    dscp = item[2]
    rfcs = item[3]

    temp = list()
    for rfc in filter(None, re.split(r'\[|\]', rfcs)):
        if 'RFC' in rfc:
            temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
        else:
            temp.append('[{}]'.format(rfc))
    desc = " {}".format(''.join(temp)) if rfcs else ''
    dscp = ' {}'.format(dscp) if dscp else ''

    try:
        temp = int(item[0], base=16)
        code = hexlify(temp)
        renm = rename(name, code)

        pres = "{}[{!r}] = {}".format(NAME, renm, code).ljust(76)
        sufs = '#{}{}'.format(desc, dscp) if desc or dscp else ''

        enum.append('{}{}'.format(pres, sufs))
    except ValueError:
        start, stop = map(lambda s: int(s, base=16), item[0].split('-'))

        miss.append('if {} <= value <= {}:'.format(hexlify(start), hexlify(stop)))
        if desc or dscp:
            miss.append('#{}{}'.format(desc, dscp))
        miss.append('    temp = hex(value)[2:].upper().zfill(8)')
        miss.append(
            "    extend_enum(cls, '{} [0x%s]' % (temp[:4]+'_'+temp[4:]), value)".format(name))
        miss.append('    return cls(value)')


###############
# Defaults
###############


ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))
with open(os.path.join(ROOT, '../_common/{}'.format(FILE)), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
