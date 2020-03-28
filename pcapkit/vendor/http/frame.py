# -*- coding: utf-8 -*-
"""HTTP/2 Frame Type"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Frame']


def hexlify(code):
    return f'0x{hex(code)[2:].upper().zfill(2)}'


class Frame(Vendor):
    """HTTP/2 Frame Type"""

    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xFF'
    LINK = 'https://www.iana.org/assignments/http2-parameters/frame-type.csv'

    def process(self, data):
        reader = csv.reader(data)
        next(reader)  # header

        enum = list()
        miss = list()
        for item in reader:
            name = item[1]
            rfcs = item[2]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc:
                    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                else:
                    temp.append(f'[{rfc}]')
            desc = f"# {''.join(temp)}" if rfcs else ''

            try:
                temp = int(item[0], base=16)
                code = hexlify(temp)
                renm = self.rename(name, code)

                pres = f"{self.NAME}[{renm!r}] = {code}"
                sufs = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                if len(pres) > 74:
                    sufs = f"\n{' '*80}{sufs}"

                enum.append(f'{pres.ljust(76)}{sufs}')
            except ValueError:
                start, stop = map(lambda s: int(s, base=16), item[0].split('-'))
                more = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                miss.append(f'if {hexlify(start)} <= value <= {hexlify(stop)}:')
                if more:
                    miss.append(f'    {more}')
                miss.append(
                    f"    extend_enum(cls, '{name} [0x%s]' % hex(value)[2:].upper().zfill(2), value)")
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Frame()
