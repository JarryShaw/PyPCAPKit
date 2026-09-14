# -*- coding: utf-8 -*-
"""Transform Type 3 - Integrity Algorithm Transform IDs
========================================================

.. module:: pcapkit.vendor.esp.integrity

This module contains the vendor crawler for **Transform Type 3 - Integrity Algorithm Transform IDs**,
which is automatically generating :class:`pcapkit.const.esp.integrity.Integrity`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Integrity']

#: Reference cells that name no document.
UNKNOWN = ('', '-', 'UNSPECIFIED')


class Integrity(Vendor):
    """Transform Type 3 - Integrity Algorithm Transform IDs"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters-7.csv'

    @staticmethod
    def rfcs(text: 'str') -> 'str':
        """Render the citations of a registry cell as reStructuredText.

        Args:
            text: Raw ``Status`` or ``Reference`` cell. IANA wraps long cells,
                so the text may hold embedded newlines.

        Returns:
            The cell with its ``[RFCxxxx]`` citations turned into
            :rst:role:`rfc` roles, or an empty string when the cell names no
            document at all.

        """
        text = re.sub(r'\]\s+\[', '][', re.sub(r'\s+', ' ', text)).strip()
        if text.upper() in UNKNOWN:
            return ''
        return re.sub(r'\[RFC(\d+)\]',
                      lambda match: f'[:rfc:`{match.group(1)}`]', text).replace('_', ' ')

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        The registry's columns are ``Number``, ``Name``, ``Status`` and
        ``Reference``.

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
            status = self.rfcs(item[2])
            refs = self.rfcs(item[3])

            desc = self.wrap_comment(' '.join(filter(None, (
                name, refs, f'({status})' if status else '',
            ))))

            try:
                code, _ = item[0], int(item[0])
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return extend_enum(cls, '{self.safe_name(name)}_%d' % value, value)")
                continue

            renm = self.rename(name, code)
            enum.append(f'#: {desc}\n    {renm} = {code}')

            # The registry spells every transform with an ``AUTH_`` prefix,
            # whereas ESP -- and RFC 8221, which says which of them to
            # implement -- names them without it. Both spellings are worth
            # having, so the prefix-stripped one is emitted as an alias.
            # ``NONE`` carries no prefix and so gets none.
            alias = renm[5:] if renm.startswith('AUTH_') else ''
            if alias.isidentifier():
                enum.append(f'#: Alias of :attr:`{self.NAME}.{renm}`.\n    {alias} = {code}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(Integrity())  # type: ignore[arg-type]
