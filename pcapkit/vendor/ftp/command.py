# -*- coding: utf-8 -*-

import contextlib
import csv
import os
import re

import requests

###############
# Macros
###############

NAME = 'Command'
DOCS = 'FTP Command'
LINK = 'https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions-2.csv'

###############
# Processors
###############

KIND = dict(
    a='access control',
    p='parameter setting',
    s='service execution'
)

CONF = dict(
    m='mandatory to implement',
    o='optional',
    h='historic',
)


def make(cmmd, feat, desc, kind, conf, rfcs): return f'''\
{cmmd}=Info(
        name={cmmd!r},
        feat={feat!r},
        desc={desc!r},
        type={kind!r},
        conf={conf!r},
        note={rfcs!r}
    )\
'''


page = requests.get(LINK)
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)

info = dict()
for item in reader:
    cmmd = item[0].strip('+')
    feat = item[1] or None
    desc = re.sub(r'{.*}', r'', item[2]).strip() or None
    kind = tuple(KIND.get(s) for s in item[3].split('/')) or None
    conf = CONF.get(item[4].split()[0])
    temp = list()
    for rfc in filter(lambda s: 'RFC' in s, re.split(r'\[|\]', item[5])):
        temp.append(f'[{rfc[:3]} {rfc[3:]}]')
    rfcs = tuple(temp) or None

    if cmmd == '-N/A-':
        MISS = '\n'.ljust(25).join((f"Info(name='%s' % key,",
                                    f'feat={feat!r},',
                                    f'desc={desc!r},',
                                    f'type={kind!r},',
                                    f'conf={conf!r},',
                                    f'note={rfcs!r})'))
    else:
        info[cmmd] = make(cmmd, feat, desc, kind, conf, rfcs)

###############
# Defaults
###############

temp, FILE = os.path.split(os.path.abspath(__file__))
ROOT, STEM = os.path.split(temp)

INFO = ',\n    '.join(map(lambda s: s.strip(), info.values()))


def LINE(NAME, DOCS, INFO, MISS): return f'''\
# -*- coding: utf-8 -*-

from pcapkit.corekit.infoclass import Info


class defaultInfo(Info):

    def __getitem__(self, key):
        try:
            return super().__getitem__(key)
        except KeyError:
            return {MISS}


# {DOCS}
{NAME} = defaultInfo(
    {INFO}
)
'''


with contextlib.suppress(FileExistsError):
    os.mkdir(os.path.join(ROOT, f'../const/{STEM}'))
with open(os.path.join(ROOT, f'../const/{STEM}/{FILE}'), 'w') as file:
    file.write(LINE(NAME, DOCS, INFO, MISS))
