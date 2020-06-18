# -*- coding: utf-8 -*-
"""IPv4 Option Numbers"""

import collections
import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['OptionNumber']


class OptionNumber(Vendor):
    """IP Option Numbers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ip-parameters/ip-parameters-1.csv'

    def count(self, data):
        """Count field records.

        Args:
            data (List[str]): CSV data.

        Returns:
            Counter: Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: self.safe_name(item[4]),  # pylint: disable=map-builtin-not-iterating
                                       filter(lambda item: len(item[3].split('-')) != 2, reader)))  # pylint: disable=filter-builtin-not-iterating

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
        miss = [
            "extend_enum(cls, 'Unassigned_%d' % value, value)",
            'return cls(value)'
        ]
        for item in reader:
            code = item[3]
            dscp = item[4]
            rfcs = item[5]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if re.match(r'\d+', rfc):
                    continue
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''

            abbr, name = re.split(r'\W+-\W+', dscp)
            tmp2 = re.sub(r'\[\d+\]', '', name)
            name = f'{" - " if abbr else ""}{tmp2}' if tmp2 else ''

            desc = self.wrap_comment(f'{abbr}{name}{tmp1}')

            renm = self.rename(abbr or f'Unassigned_{code}', code, original=dscp)
            pres = f"{renm} = {code}"
            sufs = f'#: {desc}'

            #if len(pres) > 74:
            #    sufs = f"\n{' '*80}{sufs}"

            #enum.append(f'{pres.ljust(76)}{sufs}')
            enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == "__main__":
    OptionNumber()
