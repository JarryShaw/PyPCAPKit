# -*- coding: utf-8 -*-
"""IGMP Type Numbers
=======================

.. module:: pcapkit.vendor.igmp.type

This module contains the vendor crawler for **IGMP Type Numbers**,
which is automatically generating :class:`pcapkit.const.igmp.type.Type`.

"""

import csv
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Type']


class Type(Vendor):
    """IGMP Type Numbers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers-1.csv'

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        The registry's ``Type`` column is hexadecimal (``0x11``, or a range
        such as ``0x01-0x08``), unlike the decimal columns
        :meth:`~pcapkit.vendor.default.Vendor.process` parses by default, so
        this overrides it to read every code and range endpoint with
        :func:`int` in base 16.

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
            rfcs = item[2]

            temp = []  # type: list[str]
            for ref in self.split_references(rfcs):
                if ref.startswith('RFC') and ref[3:].isdigit():
                    temp.append(f'[:rfc:`{ref[3:]}`]')
                else:
                    temp.append(f'[{ref}]'.replace('_', ' '))
            desc = self.wrap_comment('%s %s' % (  # pylint: disable=consider-using-f-string
                name, ''.join(temp) if rfcs else '',
            ))

            if '-' in item[0]:
                start, stop = item[0].split('-')
                miss.append(f'if {int(start, 16)} <= value <= {int(stop, 16)}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(name)}')")
                continue

            code = str(int(item[0], 16))
            renm = self.rename(name, code)
            enum.append(f'#: {desc}\n    {renm} = {code}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(Type())  # type: ignore[arg-type]
