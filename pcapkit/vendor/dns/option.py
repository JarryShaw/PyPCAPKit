# -*- coding: utf-8 -*-
"""DNS EDNS0 Option Codes (OPT)
==================================

.. module:: pcapkit.vendor.dns.option

This module contains the vendor crawler for **DNS EDNS0 Option Codes (OPT)**,
which is automatically generating :class:`pcapkit.const.dns.option.Option`.

The registry is IANA's ``DNS EDNS0 Option Codes (OPT)`` table, a four-column
CSV -- ``Value, Name, Status, Reference`` -- so this crawler reads the
reference at index ``3``. The names keep the registrar's spelling, with ``-``
and spaces read as ``_`` (``edns_client_subnet``, ``Extended_DNS_Error``).

A URL reference longer than a comment line can hold is cut at its fragment:
:meth:`~pcapkit.vendor.default.Vendor.wrap_comment` would otherwise split it
inside, and the joined lines of a ``#:`` comment would render it with a space
in it. The Cisco references for ``Umbrella Ident`` and ``DeviceID`` are such.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Option']

#: Longest URL reference a comment line holds whole, with its brackets.
URL_LIMIT = 74


class Option(Vendor):
    """DNS EDNS0 Option Codes (OPT)"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/dns-parameters/dns-parameters-11.csv'

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

            temp = []  # type: list[str]
            for rfc in self.split_references(rfcs):
                if rfc.startswith(('http://', 'https://')) and len(rfc) > URL_LIMIT:
                    rfc = rfc.split('#', maxsplit=1)[0]
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
    sys.exit(Option())  # type: ignore[arg-type]
