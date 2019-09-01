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

make = lambda cmmd, feat, desc, kind, conf, rfcs: '''\
{}=Info(
        name={!r},
        feat={!r},
        desc={!r},
        type={!r},
        conf={!r},
        note={!r}
    )\
'''.format(cmmd, cmmd, feat, desc, kind, conf, rfcs)

LINE = lambda NAME, DOCS, INFO, MISS: '''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""{}"""

from pcapkit.corekit.infoclass import Info


class defaultInfo(Info):

    def __getitem__(self, key):
        try:
            return super().__getitem__(key)
        except KeyError:
            return {}


# {}
{} = defaultInfo(
    {}
)
'''.format(DOCS, MISS, DOCS, NAME, INFO)


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
                temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
            rfcs = tuple(temp) or None

            if cmmd == '-N/A-':
                MISS = '\n'.ljust(25).join(("Info(name='%s' % key,",
                                            'feat={!r},'.format(feat),
                                            'desc={!r},'.format(desc),
                                            'type={!r},'.format(kind),
                                            'conf={!r},'.format(conf),
                                            'note={!r})'.format(rfcs)))
            else:
                info[cmmd] = make(cmmd, feat, desc, kind, conf, rfcs)
        return info, MISS

    def context(self, data):
        info, MISS = self.process(data)
        INFO = ',\n    '.join(map(lambda s: s.strip(), info.values()))  # pylint: disable=dict-values-not-iterating
        return LINE(self.NAME, self.DOCS, INFO, MISS)


if __name__ == "__main__":
    Command()
