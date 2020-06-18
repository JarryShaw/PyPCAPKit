# -*- coding: utf-8 -*-
"""FTP Command"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Command']

#: Command type.
KIND = dict(
    a='access control',
    p='parameter setting',
    s='service execution'
)

#: Conformance requirements.
CONF = dict(
    m='mandatory to implement',
    o='optional',
    h='historic',
)

#: Command entry template.
make = lambda cmmd, feat, desc, kind, conf, rfcs, cmmt: f'''\
    # {cmmt}
    {cmmd}=Info(
        name={cmmd!r},
        feat={feat!r},
        desc={desc!r},
        type={kind!r},
        conf={conf!r},
        note={rfcs!r},
    )
'''.strip()

#: Constant template of enumerate registry from IANA CSV.
LINE = lambda NAME, DOCS, INFO, MISS: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""{DOCS}"""

from pcapkit.corekit.infoclass import Info

__all__ = ['{NAME}']


class defaultInfo(Info):
    """Extended :class:`~pcapkit.corekit.infoclass.Info` with default values."""

    def __getitem__(self, key):
        """Missing keys as specified in :rfc:`3659`."""
        try:
            return super().__getitem__(key)
        except KeyError:
            return {MISS}


#: {DOCS}
{NAME} = defaultInfo(
    {INFO}
)
'''


class Command(Vendor):
    """FTP Command"""

    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions-2.csv'

    def process(self, data):
        """Process CSV data.

        Args:
            data (List[str]): CSV data.

        Returns:
            List[str]: Enumeration fields.
            List[str]: Missing fields.

        """
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
            rfcs_temp = list()
            #for rfc in filter(lambda s: 'RFC' in s, re.split(r'\[|\]', item[5])):
            #    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
            for rfc in filter(None, map(lambda s: s.strip(), re.split(r'\[|\]', item[5]))):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                    rfcs_temp.append(f'{rfc[:3]} {rfc[3:]}')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            rfcs = tuple(rfcs_temp) or None
            cmmt = f"{cmmd} {''.join(temp)}"

            if cmmd == '-N/A-':
                MISS = '\n'.ljust(25).join(("Info(name='%s' % key,",
                                            f'feat={feat!r},',
                                            f'desc={desc!r},',
                                            f'type={kind!r},',
                                            f'conf={conf!r},',
                                            f'note={rfcs!r})'))
            else:
                info[cmmd] = make(cmmd, feat, desc, kind, conf, rfcs, cmmt)
        return info, MISS

    def context(self, data):
        """Generate constant context.

        Args:
            data (List[str]): CSV data.

        Returns:
            str: Constant context.

        """
        info, MISS = self.process(data)
        INFO = ',\n    '.join(map(lambda s: s.strip(), info.values()))  # pylint: disable=dict-values-not-iterating
        return LINE(self.NAME, self.DOCS, INFO, MISS)


if __name__ == "__main__":
    Command()
