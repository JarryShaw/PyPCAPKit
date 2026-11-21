# -*- coding: utf-8 -*-
"""DNS RCODEs
================

.. module:: pcapkit.vendor.dns.rcode

This module contains the vendor crawler for **DNS RCODEs**,
which is automatically generating :class:`pcapkit.const.dns.rcode.RCode`.

The registry is IANA's ``DNS RCODEs`` table, a four-column CSV -- ``RCODE,
Name, Description, Reference`` -- whose values span the 4-bit header RCODE,
its 12-bit extension through the OPT record (:rfc:`6891#section-6.1.3`) and
the 16-bit TSIG and TKEY error fields. Two kinds of row need care:

* a value and name registered twice, as ``NotAuth`` (9) is by :rfc:`2136` and
  :rfc:`8945`, is one member whose comment carries both descriptions;
* a value registered under two names, as 16 is ``BADVERS`` (:rfc:`6891`) and
  ``BADSIG`` (:rfc:`8945`), gives the second name as an alias of the first.

The text after a comma in a ``Name`` cell, as in ``Reserved, can be allocated
by Standards Action``, is description rather than name, and is dropped from
the member name.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter
    from typing import Any

__all__ = ['RCode']


class RCode(Vendor):
    """DNS RCODEs"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/dns-parameters/dns-parameters-6.csv'

    @staticmethod
    def clean_name(raw: 'str') -> 'str':
        """Turn an IANA ``Name`` cell into a member identifier.

        Args:
            raw: Verbatim ``Name`` cell.

        Returns:
            The cell up to its first comma.

        """
        return raw.split(',', maxsplit=1)[0]

    def rows(self, data: 'list[str]') -> 'list[list[str]]':
        """Read the CSV rows, merging those that repeat a value and name.

        Args:
            data: CSV data.

        Returns:
            One ``[value, name, descriptions, references]`` row per value and
            name, in registry order; the last two are lists of the cells merged.

        """
        reader = csv.reader(data)
        next(reader)  # header

        rows = []  # type: list[list[Any]]
        index = {}  # type: dict[tuple[str, str], list[Any]]
        for item in reader:
            key = (item[0], self.clean_name(item[1]))
            if key in index:
                index[key][2].append(item[2])
                index[key][3].append(item[3])
                continue
            row = [item[0], item[1], [item[2]], [item[3]]]
            index[key] = row
            rows.append(row)
        return rows

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: CSV data.

        Returns:
            Field recordings.

        """
        return collections.Counter(
            self.safe_name(self.clean_name(item[1]))
            for item in self.rows(data) if len(item[0].split('-')) != 2
        )

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = []  # type: list[str]
        for item in self.rows(data):
            name = item[1]

            parts = []  # type: list[str]
            for meaning, rfcs in zip(item[2], item[3]):
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
                parts.append(' '.join(filter(None, (meaning.strip(), ''.join(temp)))))
            text = '; '.join(filter(None, parts))
            body = f'{name} -- {text}' if text else name
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
    sys.exit(RCode())  # type: ignore[arg-type]
