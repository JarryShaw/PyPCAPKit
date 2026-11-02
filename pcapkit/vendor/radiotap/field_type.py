# -*- coding: utf-8 -*-
"""Radiotap Field Types
==========================

.. module:: pcapkit.vendor.radiotap.field_type

This module contains the vendor crawler for **Radiotap Field Types**,
which is automatically generating :class:`pcapkit.const.radiotap.field_type.FieldType`.

The registry is radiotap.org's *Defined Fields* table, two columns -- the bit
number and the field name, linked to the field's own page -- scraped from
:attr:`FieldType.LINK`. A bit number is also the field's type in a TLV
(radiotap.org's *TLV fields in radiotap* page), so the registry covers both,
and the TLV-only fields from 32 on are in the same table.

To those it adds the fields of :data:`UNOFFICIAL` from radiotap.org's
*Unofficially Used Fields* table, scraped from :data:`UNOFFICIAL_LINK`, each
commented with the systems that table says generate and parse it. Bit 16 is
RTS retries there, as Linux, Wireshark and radiotap-library read it; OpenBSD
writes its RSSI field at the same bit, a 2-octet layout of its own, and the
table's other rows -- OpenBSD's FCS in header at bit 14 and FreeBSD's
XChannel at bit 18 -- are left out, since the first clashes with RX flags and
neither Linux nor Wireshark's iterator sizes the second.

The tables name no reserved value. radiotap.org's introduction reserves bits
29, 30 and 31 of every presence word, ``n * 32 - 3`` to ``n * 32 - 1``: the
first two are the namespace fields the table names, and the third chains
another presence word, so ``_missing_`` resolves the rest of those to
``Reserved`` and every other value to ``Unassigned``. The bound is the 16-bit
TLV type field; a bit number past it takes a chain of more than 2048
presence words.

"""

import collections
import sys
from typing import TYPE_CHECKING, cast

import bs4

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

    from bs4.element import Tag

__all__ = ['FieldType']

#: Link to radiotap.org's *Unofficially Used Fields* table: the bit number,
#: the field, the systems that generate it and those that parse it.
UNOFFICIAL_LINK = 'https://www.radiotap.org/fields/unofficial'

#: The fields of that table the registry takes, by name.
UNOFFICIAL = ('RTS retries', 'data retries')


class FieldType(Vendor):
    """Radiotap Field Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.radiotap.org/fields/defined'

    def request(self, text: 'str') -> 'list[Tag]':  # type: ignore[override] # pylint: disable=signature-differs
        """Fetch registry table.

        Args:
            text: Context from :attr:`~FieldType.LINK` or :data:`UNOFFICIAL_LINK`.

        Returns:
            Rows (``tr``) of the registry table, less its header row.

        """
        soup = bs4.BeautifulSoup(text, 'html5lib')
        return soup.select('table tr')[1:]

    def count(self, data: 'list[Tag]') -> 'Counter[str]':  # type: ignore[override]
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter(self.safe_name(name) for _, name, _ in self._fields(data))

    def process(self, data: 'list[Tag]') -> 'tuple[list[str], list[str]]':  # type: ignore[override]
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = [
            'if value % 32 in (29, 30, 31):',
            '    #: Reserved in every presence word',
            "    return cls._unregistered_member(value, 'Reserved')",
            "return cls._unregistered_member(value, 'Unassigned')",
        ]
        for code, name, desc in self._fields(data):
            renm = self.rename(name, str(code))
            enum.append(f'#: {self.wrap_comment(desc)}\n    {renm} = {code}')
        return enum, miss

    def _request(self) -> 'list[Tag]':  # type: ignore[override]
        """Fetch both tables, :attr:`~FieldType.LINK` then :data:`UNOFFICIAL_LINK`.

        Returns:
            Rows (``tr``) of both tables, less their header rows.

        """
        rows = cast('list[Tag]', super()._request())
        self.LINK = UNOFFICIAL_LINK
        try:
            rows += cast('list[Tag]', super()._request())
        finally:
            del self.LINK
        return rows

    def _fields(self, data: 'list[Tag]') -> 'list[tuple[int, str, str]]':
        """Pick the fields out of the rows.

        Args:
            data: Rows of both tables; a row of the unofficial one has four cells.

        Returns:
            Each field's bit number, name and description, in bit order.

        """
        fields = []  # type: list[tuple[int, str, str]]
        for row in data:
            cells = [' '.join(cell.get_text().split()) for cell in row.select('td')]
            if len(cells) == 2:
                fields.append((int(cells[0]), cells[1], cells[1]))
            elif cells[1] in UNOFFICIAL:
                code, name, generators, parsers = cells
                used = f'generated by {generators}' + (f', parsed by {parsers}' if parsers else '')
                fields.append((int(code), name, f'{name} [unofficial, {used}]'))
        return sorted(fields, key=lambda field: field[0])


if __name__ == '__main__':
    sys.exit(FieldType())  # type: ignore[arg-type]
