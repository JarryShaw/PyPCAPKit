# -*- coding: utf-8 -*-
"""TLS/DTLS Content Types
============================

.. module:: pcapkit.vendor.tls.content_type

This module contains the vendor crawler for **TLS/DTLS Content Types**,
which is automatically generating :class:`pcapkit.const.tls.content_type.ContentType`.

The registry is IANA's ``TLS ContentType`` table, a five-column CSV --
``Value, Description, DTLS-OK, Reference, Comment`` -- rather than the
three-column ``Value, Description, Reference`` shape
:meth:`~pcapkit.vendor.default.Vendor.process` assumes, so this crawler reads
the ``Reference`` column at index ``3`` instead of ``2`` and otherwise follows
the same rendering the base class uses elsewhere.

The record-layer header -- :rfc:`9846#section-5.1` for TLS, :rfc:`9147#section-4`'s
``DTLSPlaintext`` for DTLS -- opens with this type in both. Every value IANA
assigns is named; everything else in the 0-255 range the registry lists as
Unassigned (0-19 and 28-31, plus 64-255, which :rfc:`9443` reserves for
coordination with other protocols multiplexed on the same port) or as
Reserved (32-63, :rfc:`9147`), and the generated ``_missing_`` renders each
such band from the registry's own range rows rather than naming a single
catch-all member.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ContentType']


class ContentType(Vendor):
    """TLS/DTLS Content Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/tls-parameters/tls-parameters-5.csv'

    def clean_name(self, raw: 'str') -> 'str':
        """Turn an IANA ``Description`` cell into a member identifier.

        The registry's ``Description`` values are already the lower-case,
        underscore-joined wire names TLS/DTLS use (``change_cipher_spec``,
        ``heartbeat``, ...), except for ``ACK``, which IANA spells upper-case
        even though the record-layer type it names is lower-case on the wire
        like every sibling -- :rfc:`9147#section-4.1` itself writes it as
        ``ack``. Lower-casing the whole cell, rather than special-casing that
        one row, is what makes this crawler keep working if IANA adds another
        upper-case entry later.

        Args:
            raw: Verbatim ``Description`` cell.

        Returns:
            The identifier :meth:`~pcapkit.vendor.default.Vendor.rename`
            should render, before duplicate-suffixing.

        """
        return raw.split(' (', maxsplit=1)[0].lower()

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
            self.safe_name(self.clean_name(item[1]))
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
            name = item[1]
            rfcs = item[3]
            comment = item[4].strip()

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
    sys.exit(ContentType())  # type: ignore[arg-type]
