# -*- coding: utf-8 -*-
"""BOOTP Vendor Extensions and DHCP Options
==============================================

.. module:: pcapkit.vendor.dhcp.option

This module contains the vendor crawler for **BOOTP Vendor Extensions and DHCP
Options**, which is automatically generating
:class:`pcapkit.const.dhcp.option.Option`.

The registry is IANA's ``BOOTP Vendor Extensions and DHCP Options`` table, a
five-column CSV -- ``Tag, Name, Data Length, Meaning, Reference``. Several tags
hold more than one row, as tag 128 does for PXE and for the vendors IANA lists
using it; the first row names the member and the rest follow it in its comment,
so each tag is one member. A name keeps the registrar's spelling, with ``-``,
``/`` and spaces read as ``_`` (``Forward_On_Off``, ``DHCP_Msg_Type``).

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['Option']


class Option(Vendor):
    """BOOTP Vendor Extensions and DHCP Options"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/bootp-dhcp-parameters/options.csv'

    def safe_name(self, name: 'str') -> 'str':
        """Convert a ``Name`` cell to a member identifier.

        Args:
            name: Verbatim ``Name`` cell.

        Returns:
            What :meth:`~pcapkit.vendor.default.Vendor.safe_name` gives for the
            cell on one line, so that a parenthetical the registry wraps, as
            tag 175's ``(Tentatively Assigned - 2005-06-23)``, is dropped whole.

        """
        return super().safe_name(re.sub(r'\s+', ' ', name))

    def rows(self, data: 'list[str]') -> 'list[list[list[str]]]':
        """Group the registry's rows by tag.

        Args:
            data: CSV data.

        Returns:
            Each tag's rows, in the order the registry lists the tags; a range
            is one group of one row.

        """
        reader = csv.reader(data)
        next(reader)  # header

        groups = collections.OrderedDict()  # type: collections.OrderedDict[str, list[list[str]]]
        for item in reader:
            groups.setdefault(item[0].strip(), []).append(item)
        return list(groups.values())

    def describe(self, item: 'list[str]') -> 'str':
        """Render one row as its comment text.

        Args:
            item: A registry row.

        Returns:
            The name, the meaning where the row gives one, and the references.

        """
        name = re.sub(r'\s+', ' ', item[1]).strip()
        meaning = re.sub(r'\s+', ' ', item[3]).strip()
        rfcs = item[4]

        temp = []  # type: list[str]
        for rfc in self.split_references(rfcs):
            if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                temp.append(f'[:rfc:`{rfc[3:]}`]')
            else:
                temp.append(f'[{rfc}]'.replace('_', ' '))
        head = f'{name} -- {meaning}' if meaning and meaning != name and meaning != 'None' else name
        return ('%s %s' % (head, ''.join(temp) if rfcs.strip() else '')).strip()  # pylint: disable=consider-using-f-string

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: CSV data.

        Returns:
            Field recordings, of the name each tag's first row gives.

        """
        return collections.Counter(self.safe_name(group[0][1]) for group in self.rows(data)
                                   if len(group[0][0].split('-')) != 2)

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = []  # type: list[str]
        for group in self.rows(data):
            item = group[0]
            body = '; '.join(self.describe(row) for row in group)
            desc = self.wrap_comment(body)

            try:
                code, _ = item[0].strip(), int(item[0])
                renm = self.rename(item[1], code)

                enum.append(f'#: {desc}\n    {renm} = {code}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(item[1])}')")
        return enum, miss


if __name__ == '__main__':
    sys.exit(Option())  # type: ignore[arg-type]
