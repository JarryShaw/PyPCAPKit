# -*- coding: utf-8 -*-
"""HTTP/2 Error Code"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['ErrorCode']


def hexlify(code):
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
            dscp = item[2]
            rfcs = item[3]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''
            dscp = f' {dscp}' if dscp else ''
            desc = f'{name}{tmp1}{dscp}'

            try:
                temp = int(item[0], base=16)
                code = hexlify(temp)
                renm = self.rename(name, code)

                pres = f"{renm} = {code}"
                sufs = f'#: desc'

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


if __name__ == "__main__":
    ErrorCode()
