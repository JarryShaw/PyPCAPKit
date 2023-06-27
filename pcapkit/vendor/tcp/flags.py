# -*- coding: utf-8 -*-
"""TCP Header Flags
======================

.. module:: pcapkit.vendor.tcp.flags

This module contains the vendor crawler for **TCP Header Flags**,
which is automatically generating :class:`pcapkit.const.tcp.flags.Flags`.

"""

import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from typing import Callable

__all__ = ['Flags']

#: TCP header flags' abbreviation.
DATA = {
    15: 'FIN',
    14: 'SYN',
    13: 'RST',
    12: 'PSH',
    11: 'ACK',
    10: 'URG',
    9: 'ECE',
    8: 'CWR',
}

#: Default constant template of enumerate registry from IANA CSV.
LINE = lambda NAME, DOCS, ENUM, MODL: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

if TYPE_CHECKING:
    from typing import Optional

__all__ = ['{NAME}']

class {NAME}(IntFlag):
    """[{NAME}] {DOCS}"""

    {ENUM}

    @staticmethod
    def get(key: 'int | str', default: 'Optional[int]' = -1) -> '{NAME}':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Flags(key)
        return {NAME}[key]  # type: ignore[misc]
'''.strip()  # type: Callable[[str, str, str, str], str]


class Flags(Vendor):
    """TCP Header Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 4 <= value <= 15'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/tcp-parameters/tcp-header-flags.csv'

    def process(self, data: 'list[str]') -> 'list[str]':  # type: ignore[override]
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = []  # type: list[str]
        for item in reader:
            dscp = item[1]
            rfcs = item[2]

            temp = []  # type: list[str]
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if re.match(r'\d+', rfc):
                    continue
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    # temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''
            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', f'{dscp}{tmp1}', re.MULTILINE))

            code = item[0]
            name = DATA.get(int(code), dscp.split(' (')[0]).replace('Reserved for future use', 'Reserved')
            renm = self.rename(name or 'Unassigned', code, original=dscp)

            pres = f"{renm} = 1 << {code}"
            sufs = f'#: {desc}'

            # if len(pres) > 74:
            #     sufs = f"\n{' '*80}{sufs}"

            # enum.append(f'{pres.ljust(76)}{sufs}')
            enum.append(f'{sufs}\n    {pres}')
        return enum

    def context(self, data: 'list[str]') -> 'str':
        """Generate constant context.

        Args:
            data: CSV data.

        Returns:
            Constant context.

        """
        enum = self.process(data)
        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum)).strip()

        return LINE(self.NAME, self.DOCS, ENUM, self.__module__)


if __name__ == '__main__':
    sys.exit(Flags())  # type: ignore[arg-type]
