# -*- coding: utf-8 -*-
"""TLS EC Point Formats
==========================

.. module:: pcapkit.vendor.tls.ec_point_format

This module contains the vendor crawler for **TLS EC Point Formats**,
which is automatically generating :class:`pcapkit.const.tls.ec_point_format.ECPointFormat`.

The registry is IANA's ``TLS EC Point Format`` table, a five-column CSV --
``Value, Description, DTLS-OK, Reference, Comment``. Its rows are the values an
``ec_point_formats`` extension lists (:rfc:`8422#section-5.1.2`).

The crawlers of the other value sets a TLS extension lists subclass this one,
naming the columns of their own CSVs in :attr:`~ECPointFormat.REFERENCE` and
:attr:`~ECPointFormat.COMMENT`. Each keeps the registrar's spelling of a name, so
``ansiX962_compressed_prime`` keeps its case; a single-value ``Reserved`` row
takes its value as a suffix, as :meth:`~pcapkit.vendor.default.Vendor.rename`
gives it, and a range resolves to its bare label.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ECPointFormat']


class ECPointFormat(Vendor):
    """TLS EC Point Formats"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/tls-parameters/tls-parameters-9.csv'

    #: Column of the ``Reference`` cell.
    REFERENCE = 3
    #: Column of the ``Comment`` cell.
    COMMENT = 4

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: CSV data.

        Returns:
            Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(self.safe_name(item[1]) for item in reader if len(item[0].split('-')) != 2)

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
            name = item[1]
            rfcs = item[self.REFERENCE]
            comment = item[self.COMMENT].strip()

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
            if comment:
                body = '%s -- %s' % (body.strip(), comment)  # pylint: disable=consider-using-f-string
            desc = self.wrap_comment(re.sub(r'\r*\n\s*', ' ', body, flags=re.MULTILINE))

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code)

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
    sys.exit(ECPointFormat())  # type: ignore[arg-type]
