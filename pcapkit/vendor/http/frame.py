# -*- coding: utf-8 -*-
"""HTTP/2 Frame Type
=======================

.. module:: pcapkit.vendor.http.frame

This module contains the vendor crawler for **HTTP/2 Frame Type**,
which is automatically generating :class:`pcapkit.const.http.frame.Frame`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Frame']


def hexlify(code: 'int') -> 'str':
    """Convert code to hex form."""
    return f'0x{hex(code)[2:].upper().zfill(2)}'


class Frame(Vendor):
    """HTTP/2 Frame Type"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/http2-parameters/frame-type.csv'

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
                    temp_split = rfc[3:].split(', ', maxsplit=1)
                    if len(temp_split) > 1:
                        temp.append(f'[:rfc:`{temp_split[0]}#{temp_split[1].lower()}`]'.replace(' ', '-'))
                    else:
                        temp.append(f'[:rfc:`{temp_split[0]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', '``%s`` %s' % (  # pylint: disable=consider-using-f-string
                name, ''.join(temp) if rfcs else '',
            ), re.MULTILINE))

            try:
                tmp1 = int(item[0], base=16)
                code = hexlify(tmp1)
                renm = self.rename(name, code)

                pres = f"{renm} = {code}"
                sufs = f'#: {desc}'

                #if len(pres) > 74:
                #    sufs = f"\n{' '*80}{sufs}"

                #enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = map(lambda s: int(s, base=16), item[0].split('-'))

                miss.append(f'if {hexlify(start)} <= value <= {hexlify(stop)}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return extend_enum(cls, '{name}_0x%s' % hex(value)[2:].upper().zfill(2), value)")
        return enum, miss


if __name__ == '__main__':
    sys.exit(Frame())  # type: ignore[arg-type]
