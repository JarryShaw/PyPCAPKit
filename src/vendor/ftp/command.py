# -*- coding: utf-8 -*-
"""FTP Command"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Command']

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

make = lambda cmmd, feat, desc, kind, conf, rfcs: f'''\
{cmmd}=Info(
        name={cmmd!r},
        feat={feat!r},
        desc={desc!r},
        type={kind!r},
        conf={conf!r},
        note={rfcs!r}
    )\
'''

LINE = lambda NAME, DOCS, INFO, MISS: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""{DOCS}"""

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


class Command(Vendor):
    """FTP Command"""

    LINK = 'https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions-2.csv'

    def process(self, data):
        reader = csv.reader(data)
        next(reader)  # header

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
        return info, MISS

    def context(self, data):
        info, MISS = self.process(data)
        INFO = ',\n    '.join(map(lambda s: s.strip(), info.values()))  # pylint: disable=dict-values-not-iterating
        return LINE(self.NAME, self.DOCS, INFO, MISS)


if __name__ == "__main__":
    Command()
