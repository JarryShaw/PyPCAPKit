# -*- coding: utf-8 -*-
"""ICMPv6 Type Numbers
=========================

.. module:: pcapkit.vendor.icmpv6.type

This module contains the vendor crawler for **ICMPv6 Type Numbers**,
which is automatically generating :class:`pcapkit.const.icmpv6.type.Type`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Type']


class Type(Vendor):
    """ICMPv6 Type Numbers [:rfc:`4443`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters-2.csv'

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
            rfcs = item[2]

            temp = []  # type: list[str]
            for rfc in self.split_references(rfcs):
                if re.match(r'\d+', rfc):
                    continue
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''
            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', f'{name}{tmp1}', flags=re.MULTILINE))

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code)

                pres = f"{renm} = {code}"
                sufs = f'#: {desc}'

                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(name)}')")
        miss.append("return cls._unregistered_member(value, 'Unassigned')")
        return enum, miss


if __name__ == '__main__':
    sys.exit(Type())  # type: ignore[arg-type]
