# -*- coding: utf-8 -*-
"""HTTP/2 Error Code"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['ErrorCode']


def hexlify(code):
    # temp = hex(code)[2:].upper().zfill(8)
    # return f'0x{temp[:4]}_{temp[4:]}'
    return '0x{}'.format(hex(code)[2:].upper().zfill(8))


class ErrorCode(Vendor):
    """HTTP/2 Error Code"""

    FLAG = 'isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF'
    LINK = 'https://www.iana.org/assignments/http2-parameters/error-code.csv'

    def process(self, data):
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
                if 'RFC' in rfc:
                    temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
                else:
                    temp.append('[{}]'.format(rfc))
            desc = " {}".format(''.join(temp)) if rfcs else ''
            dscp = ' {}'.format(dscp) if dscp else ''

            try:
                temp = int(item[0], base=16)
                code = hexlify(temp)
                renm = self.rename(name, code)

                pres = "{}[{!r}] = {}".format(self.NAME, renm, code)
                sufs = '#{}{}'.format(desc, dscp) if desc or dscp else ''

                if len(pres) > 74:
                    sufs = "\n{}{}".format(' '*80, sufs)

                enum.append('{}{}'.format(pres.ljust(76), sufs))
            except ValueError:
                start, stop = map(lambda s: int(s, base=16), item[0].split('-'))

                miss.append('if {} <= value <= {}:'.format(hexlify(start), hexlify(stop)))
                if desc or dscp:
                    miss.append('#{}{}'.format(desc, dscp))
                miss.append('    temp = hex(value)[2:].upper().zfill(8)')
                miss.append("    extend_enum(cls, '{} [0x%s]' % (temp[:4]+'_'+temp[4:]), value)".format(name))
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    ErrorCode()
