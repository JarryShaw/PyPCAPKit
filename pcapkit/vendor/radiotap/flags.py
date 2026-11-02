# -*- coding: utf-8 -*-
"""Radiotap Flags
====================

.. module:: pcapkit.vendor.radiotap.flags

This module contains the vendor crawler for **Radiotap Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.flags.Flags`.

Each radiotap bitmap radiotap.org defines bit by bit has a flag registry, and
each registry's crawler scrapes the table on its field's page.
:class:`Flags` holds the scraping every one of them shares, and the crawlers of
the other bitmaps subclass it, naming their page and, where it holds more than
one bitmap, the subfield.

A table row whose mask sets one bit is a member. A row that sets more bits, or
that radiotap.org marks reserved or unused, is not: its bits stay undefined,
which an ``aenum.IntFlag`` keeps in a value rather than dropping, so they
round-trip. The Flags page lists its last bit in a table of its own, which the
member's comment names.

A member's value and comment come from radiotap.org, and its name from the
crawler's :attr:`~Flags.NAMES`: the macro the Linux kernel's
``include/net/ieee80211_radiotap.h`` [#]_ defines for the bit, less its
``IEEE80211_RADIOTAP_`` or ``IEEE80211_`` prefix. Where Linux defines none, the
macro is Wireshark's, from ``packet-ieee80211-radiotap-defs.h`` [#]_ or
``packet-ieee80211-radiotap.c`` [#]_; where neither does, the member takes
radiotap.org's wording of the bit, as :meth:`~Vendor.safe_name` renders it.

.. [#] Linux at commit ``e5fefa3da5bf``,
   https://github.com/torvalds/linux/blob/e5fefa3da5bf7c45bef90a3cca6a49e6c2d80877/include/net/ieee80211_radiotap.h
.. [#] Wireshark at commit ``090e75fa5daa``,
   https://gitlab.com/wireshark/wireshark/-/blob/090e75fa5daa8ec6ffc35df00c3a93c281458ece/epan/dissectors/packet-ieee80211-radiotap-defs.h
.. [#] Wireshark at commit ``aae6da75c524``,
   https://gitlab.com/wireshark/wireshark/-/blob/aae6da75c524dc8525373ae1a2bd634592e0e278/epan/dissectors/packet-ieee80211-radiotap.c

"""

import collections
import re
import sys
from typing import TYPE_CHECKING

import bs4

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter
    from typing import Callable, List, Optional, Tuple

    from bs4.element import Tag

    #: Text before a table, its column names and its rows, as
    #: :meth:`Flags.request` returns each table.
    Table = Tuple[str, List[str], List[List[str]]]

__all__ = ['Flags']

LINE = lambda NAME, DOCS, FLAG, ENUM, MODL: f'''\
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

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['{NAME}']


class {NAME}(EnumRegistry, IntFlag):
    """[{NAME}] {DOCS}"""

    {ENUM}

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not ({FLAG}):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> '{NAME}':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not ({FLAG}):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
'''  # type: Callable[[str, str, str, str, str], str]

#: Meanings radiotap.org gives a bit it leaves undefined, lower-cased.
RESERVED = re.compile(r'\(?(reserved|unused)\b')

#: Meaning radiotap.org gives a bit that means what the first column says.
SAME = '(same)'

#: A mask, as radiotap.org writes one in a table's first column.
MASK = re.compile(r'0x[0-9a-fA-F]+')

#: Prefixes of the source macros, dropped from a member's name, longest first.
PREFIXES = ('IEEE80211_RADIOTAP_', 'IEEE80211_')


class Flags(Vendor):
    """Radiotap Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/Flags.html'
    #: Subfield whose table is scraped, as the page names it before the table;
    #: :obj:`None` for every table on the page.
    SUBFIELD = None  # type: Optional[str]
    #: The source macro of each bit, keyed by mask, which is Linux's for ``0x01``
    #: to ``0x40``, and Wireshark's ``packet-ieee80211-radiotap.c`` for ``0x80``,
    #: which Linux leaves unnamed.
    NAMES = {
        0x01: 'IEEE80211_RADIOTAP_F_CFP',
        0x02: 'IEEE80211_RADIOTAP_F_SHORTPRE',
        0x04: 'IEEE80211_RADIOTAP_F_WEP',
        0x08: 'IEEE80211_RADIOTAP_F_FRAG',
        0x10: 'IEEE80211_RADIOTAP_F_FCS',
        0x20: 'IEEE80211_RADIOTAP_F_DATAPAD',
        0x40: 'IEEE80211_RADIOTAP_F_BADFCS',
        0x80: 'IEEE80211_RADIOTAP_F_SHORTGI',
    }  # type: dict[int, str]

    def request(self, text: 'str') -> 'list[Table]':  # type: ignore[override] # pylint: disable=signature-differs
        """Fetch registry tables.

        Args:
            text: Context from :attr:`~Flags.LINK`.

        Returns:
            Each table of :attr:`SUBFIELD`, as the text before it, its column
            names and its rows of cell texts. A table with no header row gets
            the column names ``mask`` and ``meaning``.

        """
        soup = bs4.BeautifulSoup(text, 'html5lib')
        tables = []  # type: list[Table]
        for table in soup.select('table'):
            caption, subfield = self._caption(table)
            if self.SUBFIELD is not None and subfield != self.SUBFIELD:
                continue
            rows = [[' '.join(' '.join(cell.stripped_strings).replace('«BR»', ' ').split())
                     for cell in row.select('td, th')] for row in table.select('tr')]
            if rows and MASK.fullmatch(rows[0][0]):
                tables.append((caption, ['mask', 'meaning'], rows))
            else:
                tables.append((caption, rows[0], rows[1:]))
        return tables

    def count(self, data: 'list[Table]') -> 'Counter[str]':  # type: ignore[override]
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter(self.safe_name(name) for _, name, _ in self._members(data))

    def process(self, data: 'list[Table]') -> 'list[str]':  # type: ignore[override]
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields.

        """
        enum = []  # type: list[str]
        for mask, name, desc in self._members(data):
            macro = self.NAMES.get(mask)
            if macro is None:
                renm = self.rename(name, f'0x{mask:x}')
            else:
                renm = next(macro[len(prefix):] for prefix in PREFIXES if macro.startswith(prefix))
            enum.append(f'#: {self.wrap_comment(desc)}\n    {renm} = 1 << {mask.bit_length() - 1}')
        return enum

    def context(self, data: 'list[Table]') -> 'str':  # type: ignore[override]
        """Generate constant context.

        Args:
            data: Registry data.

        Returns:
            Constant context.

        """
        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), self.process(data)))
        return LINE(self.NAME, self.DOCS, self.FLAG, ENUM, self.__module__)

    def _caption(self, table: 'Tag') -> 'tuple[str, Optional[str]]':
        """Name the subfield a table describes.

        Args:
            table: The table.

        Returns:
            The text of the paragraph before the table, and the subfield it
            names: the ``<code>`` word of a paragraph ``The <code>x</code>
            field ...``, or the text of the heading above the table.

        """
        caption = ''
        for elem in table.find_all_previous(['p', 'h2']):
            text = ' '.join(elem.get_text().split())
            caption = caption or text
            if elem.name == 'h2':
                return caption, text
            code = elem.find('code')
            if code is not None and text.startswith(f'The {code.get_text()} '):
                return caption, code.get_text()
        return caption, None

    def _members(self, data: 'list[Table]') -> 'list[tuple[int, str, str]]':
        """Pick the members out of the tables.

        Args:
            data: Registry data.

        Returns:
            Each member's mask, name and description, in mask order.

        """
        members = {}  # type: dict[int, tuple[str, str]]
        for number, (caption, header, rows) in enumerate(data):
            for row in rows:
                if not MASK.fullmatch(row[0]):
                    continue
                mask = int(row[0], 16)
                if mask & (mask - 1):
                    continue
                meanings = [(column, text) for column, text in zip(header[1:], row[1:])
                            if column.lower() != 'notes']
                notes = [text for column, text in zip(header[1:], row[1:]) if column.lower() == 'notes' and text]
                first = meanings[0][1]
                defined = [(column, first if text == SAME else text) for column, text in meanings
                           if not RESERVED.match((first if text == SAME else text).lower())]
                if not defined:
                    continue

                name = defined[0][1]
                if len(defined) == len(meanings) and len({text for _, text in defined}) == 1:
                    desc = name
                else:
                    # NOTE: a page with a column per PPDU kind defines some bits
                    # for some kinds only, so the comment names the kinds.
                    kinds = collections.defaultdict(list)  # type: dict[str, list[str]]
                    for column, text in defined:
                        kinds[text].append(column)
                    desc = '; '.join(f'{", ".join(columns)}: {text}' for text, columns in kinds.items())
                if notes:
                    desc = f'{desc} -- {" ".join(notes)}'
                if number:
                    desc = f'{desc} [{caption.rstrip(":")}]'
                members[mask] = (name, desc)
        return [(mask, name, desc) for mask, (name, desc) in sorted(members.items())]


if __name__ == '__main__':
    sys.exit(Flags())  # type: ignore[arg-type]
