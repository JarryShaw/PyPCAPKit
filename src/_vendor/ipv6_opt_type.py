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


NAME = 'Options'
DOCS = 'Destination Options and Hop-by-Hop Options'
FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xFF'
LINK = 'https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters-2.csv'
DATA = {
    0x00 : ('pad', 'Pad1'),                                         # [RFC 8200] 0
    0x01 : ('padn', 'PadN'),                                        # [RFC 8200]
    0x04 : ('tun', 'Tunnel Encapsulation Limit'),                   # [RFC 2473] 1
    0x05 : ('ra', 'Router Alert'),                                  # [RFC 2711] 2
    0x07 : ('calipso', 'Common Architecture Label IPv6 Security Option'),
                                                                    # [RFC 5570]
    0x08 : ('smf_dpd', 'Simplified Multicast Forwarding'),          # [RFC 6621]
    0x0F : ('pdm', 'Performance and Diagnostic Metrics'),           # [RFC 8250] 10
    0x26 : ('qs', 'Quick-Start'),                                   # [RFC 4782][RFC Errata 2034] 6
    0x63 : ('rpl', 'Routing Protocol for Low-Power and Lossy Networks'),
                                                                    # [RFC 6553]
    0x6D : ('mpl', 'Multicast Protocol for Low-Power and Lossy Networks'),
                                                                    # [RFC 7731]
    0x8B : ('ilnp', 'Identifier-Locator Network Protocol Nonce'),   # [RFC 6744]
    0x8C : ('lio', 'Line-Identification Option'),                   # [RFC 6788]
    0xC2 : ('jumbo', 'Jumbo Payload'),                              # [RFC 2675]
    0xC9 : ('home', 'Home Address'),                                # [RFC 6275]
    0xEE : ('ip_dff', 'Depth-First Forwarding'),                    # [RFC 6971]
}


###############
# Processors
###############


page = requests.get(LINK)
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)
record = collections.Counter(map(lambda item: item[4], reader))

def rename(name, code, *, original):
    if record[original] > 1:
        return f'{name} [{code}]'
    return name

reader = csv.reader(data)
header = next(reader)

enum = list()
miss = [
    "extend_enum(cls, 'Unassigned [0x%s]' % hex(value)[2:].upper().zfill(2), value)",
    'return cls(value)'
]
for item in reader:
    if not item[0]: continue

    code = item[0]
    dscp = item[4]
    rfcs = item[5]

    temp = list()
    for rfc in filter(None, re.split(r'\[|\]', rfcs)):
        if re.match(r'\d+', rfc):   continue
        if 'RFC' in rfc:
            temp.append(f'[{rfc[:3]} {rfc[3:]}]')
        else:
            temp.append(f'[{rfc}]')
    desc = f"# {''.join(temp)}" if rfcs else ''

    splt = re.split(r' \[\d+\]', dscp)[0]
    subn = re.sub(r'.* \((.*)\)', r'\1', splt)
    name = DATA.get(int(code, base=16), (str(),))[0].upper() or subn
    renm = rename(name or 'Unassigned', code, original=dscp)

    pres = f"{NAME}[{renm!r}] = {code}".ljust(76)
    sufs = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

    enum.append(f'{pres}{sufs}')


###############
# Defaults
###############


ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))
with open(os.path.join(ROOT, f'../_common/{FILE}'), 'w') as file:
    file.write(LINE(NAME, DOCS, FLAG, ENUM, MISS))
