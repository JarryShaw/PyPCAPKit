# -*- coding: utf-8 -*-
"""TCP Option Kind Numbers"""

import collections
import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Option']

#: Boolean aliases.
T, F = True, False
nm_len, op_len = None, None

#: TCP option registry.
DATA = {                             # kind  length  type  process  comment            name
    0:  (F, 'eool'),                 #   0      -      -      -                [RFC 793] End of Option List
    1:  (F, 'nop'),                  #   1      -      -      -                [RFC 793] No-Operation
    2:  (T, 'mss', nm_len, 1),       #   2      4      H      1                [RFC 793] Maximum Segment Size
    3:  (T, 'ws', nm_len, 1),        #   3      3      B      1                [RFC 7323] Window Scale
    4:  (T, 'sackpmt', nm_len),      #   4      2      ?      -       True     [RFC 2018] SACK Permitted
    5:  (T, 'sack', op_len, 0),      #   5      N      P      0      2+8*N     [RFC 2018] SACK
    6:  (T, 'echo', nm_len, 0),      #   6      6      P      0                [RFC 1072][RFC 6247] Echo
    7:  (T, 'echore', nm_len, 0),    #   7      6      P      0                [RFC 1072][RFC 6247] Echo Reply
    8:  (T, 'ts', nm_len, 2),        #   8     10     II      2                [RFC 7323] Timestamps
    9:  (T, 'poc', nm_len),          #   9      2      ?      -       True     [RFC 1693][RFC 6247] POC Permitted
    10: (T, 'pocsp', nm_len, 3),     #  10      3    ??P      3                [RFC 1693][RFC 6247] POC-Serv Profile
    11: (T, 'cc', nm_len, 0),        #  11      6      P      0                [RFC 1693][RFC 6247] Connection Count
    12: (T, 'ccnew', nm_len, 0),     #  12      6      P      0                [RFC 1693][RFC 6247] CC.NEW
    13: (T, 'ccecho', nm_len, 0),    #  13      6      P      0                [RFC 1693][RFC 6247] CC.ECHO
    14: (T, 'chkreq', nm_len, 4),    #  14      3      B      4                [RFC 1146][RFC 6247] Alt-Chksum Request
    15: (T, 'chksum', nm_len, 0),    #  15      N      P      0                [RFC 1146][RFC 6247] Alt-Chksum Data
    19: (T, 'sig', nm_len, 0),       #  19     18      P      0                [RFC 2385] MD5 Signature Option
    27: (T, 'qs', nm_len, 5),        #  27      8      P      5                [RFC 4782] Quick-Start Response
    28: (T, 'timeout', nm_len, 6),   #  28      4      P      6                [RFC 5482] User Timeout Option
    29: (T, 'ao', nm_len, 7),        #  29      N      P      7                [RFC 5925] TCP Authentication Option
    30: (T, 'mp', nm_len, 8),        #  30      N      P      8                [RFC 6824] Multipath TCP
    34: (T, 'fastopen', nm_len, 0),  #  34      N      P      0                [RFC 7413] Fast Open
}


class Option(Vendor):
    """TCP Option Kind Numbers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/tcp-parameters/tcp-parameters-1.csv'

    def count(self, data):
        """Count field records.

        Args:
            data (List[str]): CSV data.

        Returns:
            Counter: Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: self.safe_name(item[2]), reader))  # pylint: disable=map-builtin-not-iterating

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
            dscp = item[2]
            rfcs = item[3]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if re.match(r'\d+', rfc):
                    continue
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''
            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', f'{dscp}{tmp1}', re.MULTILINE))

            name = dscp.split(' (')[0]
            try:
                code, _ = item[0], int(item[0])
                name = DATA.get(int(code), (None, str()))[1].upper() or name
                renm = self.rename(name or 'Unassigned', code, original=dscp)

                pres = f"{renm} = {code}"
                sufs = f'#: {desc}'

                # if len(pres) > 74:
                #     sufs = f"\n{' '*80}{sufs}"

                # enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    extend_enum(cls, '{name}_%d' % value, value)")
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Option()
