# -*- coding: utf-8 -*-
"""ICMP Time Exceeded Codes
==============================

.. module:: pcapkit.vendor.icmp.time_exceeded_code

This module contains the vendor crawler for **ICMP Time Exceeded Codes**,
which is automatically generating
:class:`pcapkit.const.icmp.time_exceeded_code.TimeExceededCode`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['TimeExceededCode']


class TimeExceededCode(Vendor):
    """ICMP Time Exceeded Codes [:rfc:`792`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/icmp-parameters/icmp-parameters-codes-11.csv'

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
        miss = [
            "return cls._unregistered_member(value, 'Unassigned')",
        ]
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
        return enum, miss


if __name__ == '__main__':
    sys.exit(TimeExceededCode())  # type: ignore[arg-type]
