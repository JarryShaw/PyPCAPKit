# -*- coding: utf-8 -*-
"""TLS/DTLS ExtensionType Values
==================================

.. module:: pcapkit.vendor.tls.extension_type

This module contains the vendor crawler for **TLS/DTLS ExtensionType Values**,
which is automatically generating
:class:`pcapkit.const.tls.extension_type.ExtensionType`.

The registry is IANA's ``TLS ExtensionType Values`` table, a seven-column CSV --
``Value, Extension Name, TLS 1.3, DTLS-Only, Recommended, Reference, Comment``
-- rather than the three-column ``Value, Description, Reference`` shape
:meth:`~pcapkit.vendor.default.Vendor.process` assumes, so this crawler reads
the ``Reference`` column at index ``5`` and the ``Comment`` column at index
``6``, and otherwise follows the same rendering the base class uses elsewhere.

The ``Extension Name`` cells are the wire names :rfc:`9846#section-4.3` and the
extension RFCs spell, and keep the registrar's own case (``TLMSP``). Two kinds
of parenthetical need care, since :meth:`~pcapkit.vendor.default.Vendor.safe_name`
drops a parenthetical outright:

* ``(renamed from "...")`` records a former name, which is dropped, so
  ``supported_groups`` and ``session_ticket`` keep their current names;
* ``(deprecated)`` is what tells value ``53`` apart from the ``connection_id``
  at ``54`` that replaced it (:rfc:`9146`), so it is kept as a
  ``_deprecated`` suffix rather than leaving the two to collide.

The single-value ``Reserved`` rows -- the GREASE values :rfc:`8701` reserves,
and the code points :rfc:`9847` retired -- become members suffixed with their
value, as :meth:`~pcapkit.vendor.default.Vendor.rename` does for every
``Reserved`` row; the ``Unassigned`` and ``Reserved for Private Use`` ranges
resolve to the bare label.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ExtensionType']

#: A ``(renamed from "...")`` parenthetical, which records a former name.
RENAMED = re.compile(r'\s*\(renamed from [^)]*\)')

#: Any other parenthetical, e.g. ``(deprecated)``, kept as a name suffix.
QUALIFIER = re.compile(r'\s*\(([^)]*)\)')


class ExtensionType(Vendor):
    """TLS/DTLS ExtensionType Values"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values-1.csv'

    def clean_name(self, raw: 'str') -> 'str':
        """Turn an IANA ``Extension Name`` cell into a member identifier.

        Drops a ``(renamed from "...")`` parenthetical and turns any other
        into a suffix, as the module docstring describes.

        Args:
            raw: Verbatim ``Extension Name`` cell.

        Returns:
            The identifier :meth:`~pcapkit.vendor.default.Vendor.rename`
            should render, before duplicate-suffixing.

        """
        return QUALIFIER.sub(r'_\1', RENAMED.sub('', raw))

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
            rfcs = item[5]
            comment = item[6].strip()

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
            body = '%s %s' % (RENAMED.sub('', name), ''.join(temp) if rfcs else '')  # pylint: disable=consider-using-f-string
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
    sys.exit(ExtensionType())  # type: ignore[arg-type]
