# -*- coding: utf-8 -*-
"""HTTP/2 Settings
=====================

.. module:: pcapkit.vendor.http.setting

This module contains the vendor crawler for **HTTP/2 Settings**,
which is automatically generating :class:`pcapkit.const.http.setting.Setting`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Setting']


def hexlify(code: 'int') -> 'str':
    """Convert code to hex form."""
    return f'0x{hex(code)[2:].upper().zfill(4)}'


class Setting(Vendor):
    """HTTP/2 Settings"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/http2-parameters/settings.csv'

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
            dscp = item[2]
            rfcs = item[3]

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
            tmp1 = f" {''.join(temp)}" if rfcs else ''
            subs = re.sub(r'\(|\)', '', dscp)
            dscp = f' (Initial Value: {subs})' if subs else ''
            desc = self.wrap_comment(f'``{name}``{tmp1}{dscp}')

            try:
                tmp2 = int(item[0], base=16)
                code = hexlify(tmp2)
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
                miss.append(f"    return extend_enum(cls, '{self.safe_name(name)}_0x%s' % hex(value)[2:].upper().zfill(4), value)")  # pylint: disable=line-too-long
        return enum, miss


if __name__ == '__main__':
    sys.exit(Setting())  # type: ignore[arg-type]
