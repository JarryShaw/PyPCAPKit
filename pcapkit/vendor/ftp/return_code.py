# -*- coding: utf-8 -*-
"""FTP Server Return Code
============================

This module contains the vendor crawler for **FTP Server Return Code**,
which is automatically generating :class:`pcapkit.const.ftp.return_code.ReturnCode`.

"""

import collections
import sys
from typing import TYPE_CHECKING

import bs4

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter
    from typing import Callable

    from bs4 import BeautifulSoup

__all__ = ['ReturnCode']

LINE = lambda NAME, DOCS, FLAG, ENUM, MODL: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['{NAME}']

#: Response kind; whether the response is good, bad or incomplete.
KIND = {{
    '1': 'Positive Preliminary',
    '2': 'Positive Completion',
    '3': 'Positive Intermediate',
    '4': 'Transient Negative Completion',
    '5': 'Permanent Negative Completion',
    '6': 'Protected',
}}  # type: dict[str, str]

#: Grouping information.
INFO = {{
    '0': 'Syntax',
    '1': 'Information',
    '2': 'Connections',
    '3': 'Authentication and accounting',
    '4': 'Unspecified',                     # [RFC 959]
    '5': 'File system',
}}  # type: dict[str, str]


class {NAME}(IntEnum):
    """[{NAME}] {DOCS}"""

    {ENUM}

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> '{NAME}':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        """
        if isinstance(key, int):
            return {NAME}(key)
        if key not in {NAME}._member_map_:  # pylint: disable=no-member
            extend_enum({NAME}, key, default)
        return {NAME}[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> '{NAME}':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not ({FLAG}):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        code = str(value)
        kind = KIND.get(code[0], 'Reserved')
        info = INFO.get(code[1], 'Reserved')
        extend_enum(cls, '%s - %s [%s]' % (kind, info, value), value)
        return cls(value)
'''  # type: Callable[[str, str, str, str, str], str]


class ReturnCode(Vendor):
    """FTP Server Return Code"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 100 <= value <= 659'
    #: Link to registry.
    LINK = 'https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes'

    def request(self, text: 'str') -> 'BeautifulSoup':  # type: ignore[override] # pylint: disable=signature-differs
        """Fetch registry data.

        Args:
            text: Context from :attr:`~ReturnCode.LINK`.

        Returns:
            Parsed HTML source.

        """
        return bs4.BeautifulSoup(text, 'html5lib')

    def context(self, soup: 'BeautifulSoup') -> 'str':  # pylint: disable=arguments-differ,arguments-renamed
        """Generate constant context.

        Args:
            soup: Parsed HTML source.

        Returns:
            Constant context.

        """
        enum = self.process(soup)
        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum))
        return LINE(self.NAME, self.DOCS, self.FLAG, ENUM, self.__module__)

    def process(self, soup: 'BeautifulSoup') -> 'list[str]':  # type: ignore[override] # pylint: disable=arguments-differ,arguments-renamed
        """Process registry data.

        Args:
            soup: Parsed HTML source.

        Returns:
            Enumeration fields.

        """
        table = soup.find_all('table', class_='wikitable')[2]
        content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)
        next(content)  # header

        enum = []  # type: list[str]
        for item in content:
            line = item.find_all('td')

            code = ' '.join(line[0].stripped_strings)
            if len(code) != 3:
                continue

            #desc = f"{' '.join(line[1].stripped_strings).split('.')[0].strip()}."
            #enum.append(f'{self.NAME}[{self.rename(desc, code)!r}] = {code}')

            sufs = self.wrap_comment('. '.join(map(lambda s: s.strip(), ' '.join(line[1].stripped_strings).split('.'))).replace('e. g. ,', 'e.g.,'))  # pylint: disable=line-too-long
            pref = f"CODE_{code} = {code}"

            enum.append(f'#: {sufs}\n    {pref}')
        return enum

    def count(self, soup: 'BeautifulSoup') -> 'Counter[str]':  # pylint: disable=arguments-differ,arguments-renamed,unused-argument
        """Count field records."""
        #table = soup.find_all('table', class_='wikitable')[2]
        #content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)
        #next(content)  # header

        #temp = list()
        #for item in content:
        #    line = item.find_all('td')

        #    code = ' '.join(line[0].stripped_strings)
        #    if len(code) != 3:
        #        continue
        #    desc = f"{' '.join(line[1].stripped_strings).split('.')[0].strip()}."
        #    temp.append(desc)
        #return collections.Counter(temp)
        return collections.Counter()


if __name__ == '__main__':
    sys.exit(ReturnCode())
