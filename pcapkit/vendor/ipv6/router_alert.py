# -*- coding: utf-8 -*-
"""IPv6 Router Alert Option Values
=====================================

.. module:: pcapkit.vendor.ipv6.router_alert

This module contains the vendor crawler for **IPv6 Router Alert Option Values**,
which is automatically generating :class:`pcapkit.const.ipv6.router_alert.RouterAlert`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['RouterAlert']


class RouterAlert(Vendor):
    """IPv6 Router Alert Option Values"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ipv6-routeralert-values/ipv6-routeralert-values-1.csv'

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
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', '%s %s' % (  # pylint: disable=consider-using-f-string
                name, ''.join(temp) if rfcs else '',
            ), re.MULTILINE))

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code)

                pres = f"{renm} = {code}"
                sufs = f'#: {desc}'

                #if len(pres) > 74:
                #    sufs = f"\n{' '*80}{sufs}"

                #enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = map(int, item[0].split('-'))

                if 'Level' in name:
                    base = name.rstrip('s 0-31')
                    for tmp_code in range(start, stop+1):
                        renm = self.safe_name(f'{base}_{tmp_code-start}')
                        pres = f"{renm} = {tmp_code}"

                        #if len(pres) > 74:
                        #    sufs = f"\n{' '*80}{sufs}"

                        #enum.append(f'{pres.ljust(76)}{sufs}')
                        enum.append(f'#: {desc}\n    {pres}')
                else:
                    miss.append(f'if {start} <= value <= {stop}:')
                    miss.append(f'    #: {desc}')
                    miss.append(f"    return extend_enum(cls, '{name}_%d' % value, value)")
        return enum, miss


if __name__ == '__main__':
    sys.exit(RouterAlert())  # type: ignore[arg-type]
