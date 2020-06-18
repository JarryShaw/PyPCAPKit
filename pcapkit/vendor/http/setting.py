# -*- coding: utf-8 -*-
"""HTTP/2 Settings"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Setting']


def hexlify(code):
    """Convert code to hex form."""
    return f'0x{hex(code)[2:].upper().zfill(4)}'


class Setting(Vendor):
    """HTTP/2 Settings"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/http2-parameters/settings.csv'

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
            subs = re.sub(r'\(|\)', '', dscp)
            dscp = f' {subs}' if subs else ''
            desc = self.wrap_comment(f'{name}{tmp1}{dscp}')

            try:
                temp = int(item[0], base=16)
                code = hexlify(temp)
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
                miss.append(f"    extend_enum(cls, '{self.safe_name(name)}_0x%s' % hex(value)[2:].upper().zfill(4), value)")
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Setting()
