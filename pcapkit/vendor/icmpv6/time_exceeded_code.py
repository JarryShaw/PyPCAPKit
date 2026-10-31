# -*- coding: utf-8 -*-
"""ICMPv6 Time Exceeded Codes
================================

.. module:: pcapkit.vendor.icmpv6.time_exceeded_code

This module contains the vendor crawler for **ICMPv6 Time Exceeded
Codes**, which is automatically generating
:class:`pcapkit.const.icmpv6.time_exceeded_code.TimeExceededCode`.

"""

import csv
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['TimeExceededCode']


class TimeExceededCode(Vendor):
    """ICMPv6 Time Exceeded Codes [:rfc:`4443`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters-codes-4.csv'

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        Unlike the other ICMP/ICMPv6 code registries, this one's IANA CSV
        export carries no ``Reference`` column -- just ``Code,Name`` -- so
        this override skips the RFC-citation handling the others do instead
        of indexing a column that is not there.

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
            desc = self.wrap_comment(name)

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
