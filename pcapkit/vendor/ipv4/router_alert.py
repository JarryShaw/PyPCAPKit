# -*- coding: utf-8 -*-
"""IPv4 Router Alert Option Values"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['RouterAlert']


class RouterAlert(Vendor):
    """IPv4 Router Alert Option Values"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ip-parameters/ipv4-router-alert-option-values.csv'

    def process(self, data):
        """Process CSV data.

        Args:
            data (List[str]): CSV data.

        Returns:
            List[str]: Enumeration fields.
            List[str]: Missing fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = list()
        miss = list()
        for item in reader:
            name = item[1]
            rfcs = item[2]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            desc = f"#: {''.join(temp)}" if rfcs else ''

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code)

                pres = f"{self.NAME}[{renm!r}] = {code}"
                sufs = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                #if len(pres) > 74:
                #    sufs = f"\n{' '*80}{sufs}"

                #enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = map(int, item[0].split('-'))
                sufs = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                if 'Level' in name:
                    base = name.rstrip('s 0-31')
                    for code in range(start, stop+1):
                        renm = self._safe_name(f'{base} {code-start}')
                        pres = f"{self.NAME}[{renm!r}] = {code}"

                        #if len(pres) > 74:
                        #    sufs = f"\n{' '*80}{sufs}"

                        #enum.append(f'{pres.ljust(76)}{sufs}')
                        enum.append(f'{sufs}\n    {pres}')
                else:
                    miss.append(f'if {start} <= value <= {stop}:')
                    if sufs:
                        miss.append(f'    {sufs}')
                    miss.append(f"    extend_enum(cls, '{name} [%d]' % value, value)")
                    miss.append('    return cls(value)')
        return enum, miss


if __name__ == '__main__':
    RouterAlert()
