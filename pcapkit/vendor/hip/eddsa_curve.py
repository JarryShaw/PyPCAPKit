# -*- coding: utf-8 -*-
"""EdDSA Curve Label
===========================

.. module:: pcapkit.const.hip.eddsa_curve

This module contains the vendor crawler for **EdDSA Curve Label**,
which is automatically generating :class:`pcapkit.const.hip.eddsa_curve.EdDSACurve`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['EdDSACurve']


class EdDSACurve(Vendor):
    """EdDSA Curve Label"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/eddsa-curve-label.csv'

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields and missing fields.

        """
        reader = csv.reader(data)
        next(reader)

        enum = []  # type: list[str]
        miss = []  # type: list[str]
        for item in reader:
            name = item[1]
            rfcs = item[3]

            temp = []  # type: list[str]
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    # temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp_split = rfc[3:].split(', ', maxsplit=1)
                    if len(temp_split) > 1:
                        temp.append(f'[:rfc:`{temp_split[0]}#{temp_split[1].lower()}`]'.replace(' ', '-'))
                    else:
                        temp.append(f'[:rfc:`{temp_split[0]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', '%s %s' % (  # pylint: disable=consider-using-f-string
                name, ''.join(temp) if rfcs else '',
            ), re.MULTILINE))

            try:
                code, _ = item[2], int(item[2])
                renm = self.rename(name, code)

                pres = f'{renm} = {code}'
                sufs = f'#: {desc}'

                # if len(pres) > 74:
                #    sufs = f"\n{' '*80}{sufs}"

                # enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[2].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return extend_enum(cls, '{self.safe_name(name)}_%d' % value, value)")
        return enum, miss


if __name__ == '__main__':
    sys.exit(EdDSACurve())  # type: ignore[arg-type]
