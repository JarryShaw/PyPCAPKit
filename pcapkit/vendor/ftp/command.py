# -*- coding: utf-8 -*-
"""FTP Command
=================

This module contains the vendor crawler for **FTP Command**,
which is automatically generating :class:`pcapkit.const.ftp.command.Command`.

"""

import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from typing import Callable, Optional

__all__ = ['Command']

#: Command type.
KIND = {
    'a': 'access control',
    'p': 'parameter setting',
    's': 'service execution',
}  # type: dict[str, str]

#: Conformance requirements.
CONF = {
    'm': 'mandatory to implement',
    'o': 'optional',
    'h': 'historic',
}  # type: dict[str, str]

#: Command entry template.
make = lambda cmmd, feat, desc, kind, conf, rfcs, cmmt: f'''\
    # {cmmt}
    {cmmd}=CommandType(
        name={cmmd!r},
        feat={feat!r},
        desc={desc!r},
        type={kind!r},
        conf={conf!r},
        note={rfcs!r},
    ),
'''.strip()  # type: Callable[[str, Optional[str], Optional[str], Optional[tuple[str, ...]], Optional[str], Optional[tuple[str, ...]], str], str] # pylint: disable=line-too-long

#: Constant template of enumerate registry from IANA CSV.
LINE = lambda NAME, DOCS, INFO, MISS, MODL: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

if TYPE_CHECKING:
    from typing import Optional

__all__ = ['{NAME}']


class CommandType(Info):
    """FTP command type."""

    #: Name of command.
    name: 'str'
    #: Feature of command.
    feat: 'Optional[str]'
    #: Description of command.
    desc: 'Optional[str]'
    #: Type of command.
    type: 'Optional[tuple[str, ...]]'
    #: Conformance of command.
    conf: 'Optional[str]'
    #: Note of command.
    note: 'Optional[tuple[str, ...]]'

    if TYPE_CHECKING:
        def __init__(self, name: 'str', feat: 'Optional[str]', desc: 'Optional[str]', type: 'Optional[tuple[str, ...]]', conf: 'Optional[str]', note: 'Optional[tuple[str, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class defaultInfo(Info[CommandType]):
    """Extended :class:`~pcapkit.corekit.infoclass.Info` with default values.

    Args:
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    """

    def __getitem__(self, key: 'str') -> 'CommandType':
        """Missing keys as specified in :rfc:`3659`.

        Args:
            key: Key of missing command.

        """
        try:
            return super().__getitem__(key)
        except KeyError:
            return {MISS}


#: {DOCS}
{NAME} = defaultInfo(
    {INFO}
)
'''  # type: Callable[[str, str, str, str, str], str]


class Command(Vendor):
    """FTP Command"""

    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions-2.csv'

    def process(self, data: 'list[str]') -> 'tuple[dict[str, str], str]':  # type: ignore[override]
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields and missing fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        info = {}  # type: dict[str, str]
        for item in reader:
            cmmd = item[0].strip('+')
            feat = item[1] or None
            desc = re.sub(r'{.*}', r'', item[2]).strip() or None
            kind = tuple(KIND[s] for s in item[3].split('/') if s in KIND) or None
            conf = CONF.get(item[4].split()[0])

            temp = []  # type: list[str]
            rfcs_temp = []  # type: list[str]
            #for rfc in filter(lambda s: 'RFC' in s, re.split(r'\[|\]', item[5])):
            #    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
            for rfc in filter(None, map(lambda s: s.strip(), re.split(r'\[|\]', item[5]))):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                    rfcs_temp.append(f'{rfc[:3]} {rfc[3:]}')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            rfcs = tuple(rfcs_temp) or None
            cmmt = self.wrap_comment('%s %s' % (cmmd, ''.join(temp)))  # pylint: disable=consider-using-f-string

            if cmmd == '-N/A-':
                MISS = '\n'.ljust(32).join(("CommandType(name=key,",
                                            f'feat={feat!r},',
                                            f'desc={desc!r},',
                                            f'type={kind!r},',
                                            f'conf={conf!r},',
                                            f'note={rfcs!r})'))
            else:
                info[cmmd] = make(cmmd, feat, desc, kind, conf, rfcs, cmmt)
        return info, MISS

    def context(self, data: 'list[str]') -> 'str':
        """Generate constant context.

        Args:
            data: CSV data.

        Returns:
            Constant context.

        """
        info, MISS = self.process(data)
        INFO = '\n    '.join(map(lambda s: s.strip(), info.values()))
        return LINE(self.NAME, self.DOCS, INFO, MISS, self.__module__)


if __name__ == '__main__':
    sys.exit(Command())
