# -*- coding: utf-8 -*-
"""Ethertype IEEE 802 Numbers"""

import collections
import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['EtherType']


class EtherType(Vendor):
    """Ethertype IEEE 802 Numbers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers-1.csv'

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
                                       filter(lambda item: len(item[1].split('-')) != 2, reader)))  # pylint: disable=filter-builtin-not-iterating

    def rename(self, name, code):  # pylint: disable=arguments-differ
        """Rename duplicated fields.

        Args:
            name (str): Field name.
            code (str): Field code (hex).

        Keyword Args:
            original (str): Original field name (extracted from CSV records).

        Returns:
            str: Revised field name.

        """
        if self.record[self.safe_name(name)] > 1:
            name = f'{name}_0x{code}'
        return self.safe_name(name)

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
            name = item[4]
            rfcs = item[5]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = re.sub(r'( )( )*', ' ', f"{''.join(temp)}".replace('\n', ' ')) if rfcs else ''
            tmp2 = re.sub(r'\r*\n', ' ', tmp1, re.MULTILINE)
            tmp3 = name.replace('\n', ' ')
            desc = self.wrap_comment(f"{tmp3} {tmp2}")

            try:
                code, _ = item[1], int(item[1], base=16)
                renm = re.sub(r'( )( )*', ' ', self.rename(name, code).replace('\n', ' '))

                pres = f'{renm} = 0x{code}'
                sufs = f'#: {desc}'

                # if len(pres) > 74:
                #     sufs = f"\n{' '*80}{sufs}"

                # enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[1].split('-')

                miss.append(f'if 0x{start} <= value <= 0x{stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    extend_enum(cls, '{self.safe_name(name)}_0x%s' % hex(value)[2:].upper().zfill(4), value)")
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    EtherType()
