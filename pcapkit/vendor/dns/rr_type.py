# -*- coding: utf-8 -*-
"""DNS Resource Record (RR) TYPEs
====================================

.. module:: pcapkit.vendor.dns.rr_type

This module contains the vendor crawler for **DNS Resource Record (RR) TYPEs**,
which is automatically generating :class:`pcapkit.const.dns.rr_type.RRType`.

The registry is IANA's ``Resource Record (RR) TYPEs`` table, a six-column CSV --
``TYPE, Value, Meaning, Reference, Template, Registration Date`` -- whose first
column is the mnemonic and second the value, the reverse of the ``Value,
Description, Reference`` shape :meth:`~pcapkit.vendor.default.Vendor.process`
assumes. A member takes the mnemonic, the name :rfc:`1035#section-3.2.2` and
every later RFC use on the wire and in master files, with ``-`` read as ``_``
(``NSAP_PTR``); IANA's ``*`` (255) is ``ANY``, the name :rfc:`8482` gives it.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['RRType']


class RRType(Vendor):
    """DNS Resource Record (RR) TYPEs"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv'

    def clean_name(self, raw: 'str') -> 'str':
        """Turn an IANA ``TYPE`` cell into a member identifier.

        Args:
            raw: Verbatim ``TYPE`` cell.

        Returns:
            The identifier :meth:`~pcapkit.vendor.default.Vendor.rename`
            should render, before duplicate-suffixing.

        """
        return 'ANY' if raw.strip() == '*' else raw

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
            self.safe_name(self.clean_name(item[0]))
            for item in reader if len(item[1].split('-')) != 2
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
            name = item[0]
            rfcs = item[3]
            meaning = item[2].strip()

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
            head = f'{name} -- {meaning}' if meaning else name
            body = '%s %s' % (head, ''.join(temp) if rfcs else '')  # pylint: disable=consider-using-f-string
            desc = self.wrap_comment(re.sub(r'\r*\n\s*', ' ', body, flags=re.MULTILINE))

            try:
                code, _ = item[1], int(item[1])
                renm = self.rename(self.clean_name(name), code)

                pres = f'{renm} = {code}'
                sufs = f'#: {desc}'

                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[1].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(name)}')")
        return enum, miss


if __name__ == '__main__':
    sys.exit(RRType())  # type: ignore[arg-type]
