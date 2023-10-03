# -*- coding: utf-8 -*-
"""Multipath TCP options
===========================

.. module:: pcapkit.vendor.tcp.mp_tcp_option

This module contains the vendor crawler for **Multipath TCP options**,
which is automatically generating :class:`pcapkit.const.tcp.mp_tcp_option.MPTCPOption`.

"""

import csv
import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['MPTCPOption']


class MPTCPOption(Vendor):
    """Multipath TCP options [:rfc:`6824`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/tcp-parameters/mptcp-option-subtypes.csv'

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = []  # type: list[str]
        miss = []  # type: list[str]
        for item in reader:
            dscp = item[2]
            rfcs = item[3]

            temp = []  # type: list[str]
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if re.match(r'\d+', rfc):
                    continue
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    # temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    match = re.fullmatch(r'RFC(?P<rfc>\d+)(, Section (?P<sec>.*?))?', rfc)
                    if match is None:
                        temp.append(f'[{rfc}]')
                    else:
                        if match.group('sec') is not None:
                            temp.append(f'[:rfc:`{match.group("rfc")}#{match.group("sec")}`]')
                        else:
                            temp.append(f'[:rfc:`{match.group("rfc")}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''
            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', f'{dscp}{tmp1}', re.MULTILINE))

            name = item[1]
            try:
                code, _ = item[0], int(item[0], base=16)
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
                miss.append(f"    return extend_enum(cls, '{name}_%d' % value, value)")
        return enum, miss


if __name__ == '__main__':
    sys.exit(MPTCPOption())  # type: ignore[arg-type]
