# -*- coding: utf-8 -*-
"""HTTP/2 Frame Type"""

import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Frame']


def hexlify(code):
    return '0x{}'.format(hex(code)[2:].upper().zfill(2))


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
                    temp.append('[{} {}]'.format(rfc[:3], rfc[3:]))
                else:
                    temp.append('[{}]'.format(rfc))
            desc = "# {}".format(''.join(temp)) if rfcs else ''

            try:
                temp = int(item[0], base=16)
                code = hexlify(temp)
                renm = self.rename(name, code)

                pres = "{}[{!r}] = {}".format(self.NAME, renm, code)
                sufs = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                if len(pres) > 74:
                    sufs = "\n{}{}".format(' '*80, sufs)

                enum.append('{}{}'.format(pres.ljust(76), sufs))
            except ValueError:
                start, stop = map(lambda s: int(s, base=16), item[0].split('-'))
                more = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                miss.append('if {} <= value <= {}:'.format(hexlify(start), hexlify(stop)))
                if more:
                    miss.append('    {}'.format(more))
                miss.append(
                    "    extend_enum(cls, '{} [0x%s]' % hex(value)[2:].upper().zfill(2), value)".format(name))
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Frame()
