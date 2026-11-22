# -*- coding: utf-8 -*-
"""DNS CLASSes
=================

.. module:: pcapkit.vendor.dns.rr_class

This module contains the vendor crawler for **DNS CLASSes**,
which is automatically generating :class:`pcapkit.const.dns.rr_class.RRClass`.

The registry is IANA's ``DNS CLASSes`` table, a four-column CSV --
``Decimal, Hexadecimal, Name, Reference`` -- so this crawler reads the name at
index ``2`` and the reference at index ``3``. A member takes the class's
mnemonic, the name :rfc:`1035#section-3.2.4` and master files use: the
parenthetical of ``Internet (IN)`` is ``IN``, and ``QCLASS NONE`` and
``QCLASS * (ANY)`` drop their ``QCLASS`` prefix to ``NONE`` and ``ANY``, the
names :rfc:`2136#section-1.3` and :rfc:`1035#section-3.2.5` give them.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['RRClass']

#: A trailing parenthetical holding a single upper-case mnemonic, e.g. ``(IN)``.
MNEMONIC = re.compile(r'\(([A-Z]+)\)\s*$')


class RRClass(Vendor):
    """DNS CLASSes"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/dns-parameters/dns-parameters-2.csv'

    def clean_name(self, raw: 'str') -> 'str':
        """Turn an IANA ``Name`` cell into a member identifier.

        Args:
            raw: Verbatim ``Name`` cell.

        Returns:
            The identifier :meth:`~pcapkit.vendor.default.Vendor.rename`
            should render, before duplicate-suffixing.

        """
        match = MNEMONIC.search(raw)
        if match is not None:
            return match.group(1)
        return re.sub(r'\AQCLASS\s+', '', raw)

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: CSV data.

        Returns:
            Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(
            self.safe_name(self.clean_name(item[2]))
            for item in reader if len(item[0].split('-')) != 2
        )

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields and missing fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = []  # type: list[str]
        miss = []  # type: list[str]
        for item in reader:
            name = item[2]
            rfcs = item[3]

            temp = []  # type: list[str]
            for rfc in self.split_references(rfcs):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    temp_split = rfc[3:].split(', ', maxsplit=1)
                    if len(temp_split) > 1:
                        temp.append(f'[:rfc:`{temp_split[0]}#{temp_split[1].lower()}`]'.replace(' ', '-'))
                    else:
                        temp.append(f'[:rfc:`{temp_split[0]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            body = '%s %s' % (name, ''.join(temp) if rfcs else '')  # pylint: disable=consider-using-f-string
            desc = self.wrap_comment(re.sub(r'\r*\n\s*', ' ', body, flags=re.MULTILINE))

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(self.clean_name(name), code)

                pres = f'{renm} = {code}'
                sufs = f'#: {desc}'

                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(name)}')")
        return enum, miss


if __name__ == '__main__':
    sys.exit(RRClass())  # type: ignore[arg-type]
