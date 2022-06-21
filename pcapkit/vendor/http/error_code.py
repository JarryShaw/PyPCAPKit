# -*- coding: utf-8 -*-
"""HTTP/2 Error Code
=======================

This module contains the vendor crawler for **HTTP/2 Error Code**,
which is automatically generating :class:`pcapkit.const.http.error_code.ErrorCode`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['ErrorCode']


def hexlify(code: 'int') -> 'str':
    """Convert code to hex form."""
    # temp = hex(code)[2:].upper().zfill(8)
    # return f'0x{temp[:4]}_{temp[4:]}'
    return f'0x{hex(code)[2:].upper().zfill(8)}'


class ErrorCode(Vendor):
    """HTTP/2 Error Code"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/http2-parameters/error-code.csv'

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
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''
            dscp = f', {dscp}' if dscp else ''
            desc = self.wrap_comment(f'{name}{dscp}{tmp1}')

            try:
                tmp2 = int(item[0], base=16)
                code = hexlify(tmp2)
                renm = self.rename(name, code)

                pres = f'{renm} = {code}'
                sufs = f'#: {desc}'

                #if len(pres) > 74:
                #    sufs = f"\n{' '*80}{sufs}"

                #enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = map(lambda s: int(s, base=16), item[0].split('-'))

                miss.append(f'if {hexlify(start)} <= value <= {hexlify(stop)}:')
                miss.append(f'    #: {desc}')
                miss.append('    temp = hex(value)[2:].upper().zfill(8)')
                miss.append(f"    extend_enum(cls, '{self.safe_name(name)}_0x%s' % (temp[:4]+'_'+temp[4:]), value)")
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == '__main__':
    sys.exit(ErrorCode())
