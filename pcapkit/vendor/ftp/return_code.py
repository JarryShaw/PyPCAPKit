# -*- coding: utf-8 -*-
"""FTP Server Return Code
============================

.. module:: pcapkit.vendor.ftp.return_code

This module contains the vendor crawler for **FTP Server Return Code**,
which is automatically generating :class:`pcapkit.const.ftp.return_code.ReturnCode`.

"""

import collections
import re
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
# mypy: disable-error-code=assignment
# pylint: disable=line-too-long,consider-using-f-string
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

if TYPE_CHECKING:
    from typing import Optional, Type

__all__ = ['{NAME}']

#: Grouping information.
INFO = {{
    '0': 'Syntax',
    '1': 'Information',
    '2': 'Connections',
    '3': 'Authentication and accounting',
    '4': 'Unspecified',                     # [RFC 959]
    '5': 'File system',
}}  # type: dict[str, str]


class ResponseKind(EnumRegistry, IntEnum):
    """Response kind; whether the response is good, bad or incomplete."""

    PositivePreliminary = 1
    PositiveCompletion = 2
    PositiveIntermediate = 3
    TransientNegativeCompletion = 4
    PermanentNegativeCompletion = 5
    Protected = 6

    @classmethod
    def _missing_(cls, value: 'int') -> 'ResponseKind':
        """Lookup function used when value is not found.

        Args:
            value: Value to lookup.

        """
        if isinstance(value, int) and 0 <= value <= 9:
            #: Unknown
            return cls._unregistered_member(value, 'Unknown')
        return super()._missing_(value)


class GroupingInformation(EnumRegistry, IntEnum):
    """Grouping information."""

    Syntax = 0
    Information = 1
    Connections = 2
    AuthenticationAccounting = 3
    Unspecified = 4
    FileSystem = 5

    @classmethod
    def _missing_(cls, value: 'int') -> 'GroupingInformation':
        """Lookup function used when value is not found.

        Args:
            value: Value to lookup.

        """
        if isinstance(value, int) and 0 <= value <= 9:
            #: Unknown
            return cls._unregistered_member(value, 'Unknown')
        return super()._missing_(value)


class {NAME}(EnumRegistry, IntEnum):
    """[{NAME}] {DOCS}"""

    if TYPE_CHECKING:
        #: Description of the return code.
        description: 'Optional[str]'
        #: Response kind.
        kind: 'ResponseKind'
        #: Grouping information.
        group: 'GroupingInformation'

    def __new__(cls, value: 'int', description: 'Optional[str]' = None) -> 'Type[{NAME}]':
        obj = int.__new__(cls, value)
        obj._value_ = value

        code = str(value)
        obj.description = description
        obj.kind = ResponseKind(int(code[0]))
        obj.group = GroupingInformation(int(code[1]))

        return obj

    def __repr__(self) -> 'str':
        return f'<{{self.__class__.__name__}} [{{self._value_}}]>'

    def __str__(self) -> 'str':
        return "[%s] %s" % (self._value_, self.description)

    {ENUM}

    @classmethod
    def _unregistered_member(cls, value: 'int', name: 'str') -> '{NAME}':
        """Build a member absent from this registry's own lookup tables.

        Reconstructs :attr:`description`, :attr:`kind` and :attr:`group` the
        same way :meth:`__new__` would, rather than leaving them unset --
        :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`
        bypasses :meth:`__new__` entirely (it calls :class:`int`'s directly),
        so those three attributes would otherwise be missing from the result
        and :meth:`__str__`/:meth:`__repr__` would raise on it.

        Args:
            value: Value to get enum item.
            name: Bare label for the unregistered member, per the ranged
                mint/unmint criterion.

        """
        obj = super()._unregistered_member(value, name)
        code = str(value)
        obj.description = None
        obj.kind = ResponseKind(int(code[0]))
        obj.group = GroupingInformation(int(code[1]))
        return obj

    @classmethod
    def _missing_(cls, value: 'int') -> '{NAME}':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not ({FLAG}):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        #: Unassigned
        return cls._unregistered_member(value, 'Unassigned')
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

            # NOTE: MediaWiki renders a trailing ``|-`` row separator in the
            # wikitext as an empty ``<tr class="mw-empty-elt">``, which revision
            # 1354125851 of the article carries at the end of this table. It has
            # no cells at all, so reading ``line[0]`` raised ``IndexError`` and
            # took the whole crawler down. Skipping cell-less rows is the fix
            # rather than indexing defensively further down, because a row that
            # cannot supply both a code and an explanation has nothing to
            # contribute either way; see #518.
            if len(line) < 2:
                continue

            code = ' '.join(line[0].stripped_strings)
            if len(code) != 3:
                continue

            #desc = f"{' '.join(line[1].stripped_strings).split('.')[0].strip()}."
            #enum.append(f'{self.NAME}[{self.rename(desc, code)!r}] = {code}')

            cmmt = re.sub(r'  +', r' ', '. '.join(map(lambda s: s.strip(), ' '.join(
                line[1].stripped_strings).split('.'))).replace('e. g. ,', 'e.g.,').strip())
            sufs = self.wrap_comment(cmmt)  # pylint: disable=line-too-long

            desc = re.sub(r'\(.*\)', r'', cmmt.split('.', maxsplit=1)[0]).strip() + '.'
            pref = f"CODE_{code}: 'ReturnCode' = {code}, {desc!r}"

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
    sys.exit(ReturnCode())  # type: ignore[arg-type]
