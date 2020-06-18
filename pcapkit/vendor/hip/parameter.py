# -*- coding: utf-8 -*-
"""HIP Parameter Types"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Parameter']


class Parameter(Vendor):
    """HIP Parameter Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-4.csv'

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
            plen = item[2]
            rfcs = item[3]

            match = re.match(r'(\w*) *(\(.*\))*', long)
            group = match.groups()

            name = group[0]
            cmmt = f' {group[1]}' if group[1] else ''
            plen = f' {plen}' if re.match(r'\d+', plen) else ''

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''
            desc = self.wrap_comment(f"{name}{tmp1}{plen}{cmmt}")

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code, original=long)

                pres = f"{renm} = {code}"
                sufs = f"#: {desc}"

                #if len(pres) > 74:
                #    sufs = f"\n{' '*80}{sufs}"

                #enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f"    #: {desc}")
                miss.append(f"    extend_enum(cls, '{self.safe_name(name)}_%d' % value, value)")
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Parameter()
