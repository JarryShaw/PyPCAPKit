# -*- coding: utf-8 -*-
"""IPv4 DHCP Support Mode Flags
==================================

.. module:: pcapkit.vendor.mh.dhcp_support_mode

This module contains the vendor crawler for **IPv4 DHCP Support Mode Flags**,
which is automatically generating :class:`pcapkit.const.mh.dhcp_support_mode.DHCPSupportMode`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['DHCPSupportMode']


class DHCPSupportMode(Vendor):
    """IPv4 DHCP Support Mode Flags"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 1'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/mobility-parameters/dhcp-support-mode.csv'

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
            "return extend_enum(cls, 'Unassigned_%d' % value, value)",
        ]
        for item in reader:
            long = item[1]
            rfcs = item[2]

            temp = []  # type: list[str]
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    # temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''

            name = self.safe_name(re.sub(r'\((.+?)\)', r'\1', long))
            desc = self.wrap_comment(f'{long}{tmp1}')

            code, code_val = item[0], int(item[0], base=16)
            renm = self.rename(name, code, original=long)

            pres = f"{renm} = 0x{code_val:01x}"
            sufs = f'#: {desc}'

            # if len(pres) > 74:
            #     sufs = f"\n{' '*80}{sufs}"

            # enum.append(f'{pres.ljust(76)}{sufs}')
            enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(DHCPSupportMode())  # type: ignore[arg-type]
