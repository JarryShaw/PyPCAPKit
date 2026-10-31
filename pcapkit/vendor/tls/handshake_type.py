# -*- coding: utf-8 -*-
"""TLS/DTLS HandshakeType
============================

.. module:: pcapkit.vendor.tls.handshake_type

This module contains the vendor crawler for **TLS/DTLS HandshakeType**,
which is automatically generating
:class:`pcapkit.const.tls.handshake_type.HandshakeType`.

The registry is IANA's ``TLS HandshakeType`` table, a five-column CSV --
``Value, Description, DTLS-OK, Reference, Comment`` -- rather than the
three-column ``Value, Description, Reference`` shape
:meth:`~pcapkit.vendor.default.Vendor.process` assumes, so this crawler reads
the ``Reference`` column at index ``3`` instead of ``2`` and otherwise follows
the same rendering the base class uses elsewhere.

IANA suffixes ``_RESERVED`` onto the handful of code points TLS 1.3 retired --
it keeps the code point reserved rather than reassigning it -- which is a
statement about the registry, not a different message name, so
:meth:`HandshakeType.clean_name` strips the suffix before it reaches the
generated member name.

The registry also carries ``request_connection_id`` and ``new_connection_id``
(:rfc:`9147#section-5.2`), the DTLS-only connection-ID messages that same
section adds to this table rather than a separate one, so they need no
special handling here -- they are rows like any other.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['HandshakeType']

#: Suffix IANA appends to a ``Description`` cell for a code point TLS 1.3
#: retired, kept reserved rather than reassigned.
RESERVED_SUFFIX = '_reserved'


class HandshakeType(Vendor):
    """TLS/DTLS HandshakeType"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/tls-parameters/tls-parameters-7.csv'

    def clean_name(self, raw: 'str') -> 'str':
        """Turn an IANA ``Description`` cell into a member identifier.

        Strips the ``(renamed from "...")`` parenthetical
        :meth:`~pcapkit.vendor.default.Vendor.safe_name` would otherwise
        carry into the identifier (e.g. ``new_session_ticket``, value
        ``4``), lower-cases the cell, and drops the trailing
        :data:`RESERVED_SUFFIX` the module docstring describes.

        Args:
            raw: Verbatim ``Description`` cell.

        Returns:
            The identifier :meth:`~pcapkit.vendor.default.Vendor.rename`
            should render, before duplicate-suffixing.

        """
        name = raw.split(' (', maxsplit=1)[0].lower()
        if name.endswith(RESERVED_SUFFIX):
            name = name[:-len(RESERVED_SUFFIX)]
        return name

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
            # NOTE: the comment text, unlike the identifier, keeps the
            # registry's original case -- only the ``_RESERVED`` suffix
            # :data:`RESERVED_SUFFIX` describes is dropped, since it is a
            # statement about the registry rather than part of the message
            # name (see the module docstring).
            display = name.split(' (', maxsplit=1)[0]
            if display.upper().endswith(RESERVED_SUFFIX.upper()):
                display = display[:-len(RESERVED_SUFFIX)]
            body = '%s %s' % (display, ''.join(temp) if rfcs else '')  # pylint: disable=consider-using-f-string
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
    sys.exit(HandshakeType())  # type: ignore[arg-type]
