# -*- coding: utf-8 -*-
"""HIP Packet Types"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Packet']


class Packet(Vendor):
    """HIP Packet Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 127'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-1.csv'

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
            long = item[1]
            rfcs = item[2]

            if ' - ' in long:
                name, cmmt = long.split(' -')
            elif ' (' in long:
                cmmt, name = f" {long.strip(')')}".split(' (')
            else:
                name, cmmt = long, ''

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            desc = f" {''.join(temp)}" if rfcs else ''

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code, original=long)

                pres = f"{self.NAME}[{renm!r}] = {code}"
                sufs = f'#:{desc}{cmmt}' if desc or cmmt else ''

                #if len(pres) > 74:
                #    sufs = f"\n{' '*80}{sufs}"

                #enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                if desc or cmmt:
                    miss.append(f'    #{desc}{cmmt}')
                miss.append(f"    extend_enum(cls, '{name} [%d]' % value, value)")
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Packet()
