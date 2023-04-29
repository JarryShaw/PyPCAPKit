# -*- coding: utf-8 -*-
"""TaggerID Types
====================

.. module:: pcapkit.vendor.ipv6.tagger_id

This module contains the vendor crawler for **TaggerID Types**,
which is automatically generating :class:`pcapkit.const.ipv6.tagger_id.TaggerID`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['TaggerID']


class TaggerID(Vendor):
    """TaggerID Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 7'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ipv6-parameters/taggerId-types.csv'

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
            name = item[1] or item[2]
            rfcs = item[3]

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
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return extend_enum(cls, '{name}_%d' % value, value)")
        return enum, miss


if __name__ == '__main__':
    sys.exit(TaggerID())  # type: ignore[arg-type]
