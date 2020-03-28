# -*- coding: utf-8 -*-
"""IPv6 Seed-ID Types"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['SeedID']


class SeedID(Vendor):
    """Seed-ID Types"""

    FLAG = 'isinstance(value, int) and 0b00 <= value <= 0b11'
    DATA = {
        0b00: 'IPv6 Source Address',                   # [RFC 7731]
        0b01: '16-Bit Unsigned Integer',               # [RFC 7731]
        0b10: '64-Bit Unsigned Integer',               # [RFC 7731]
        0b11: '128-Bit Unsigned Integer',              # [RFC 7731]
    }

    def request(self):  # pylint: disable=arguments-differ
        return self.DATA

    def count(self, data):
        return collections.Counter(data.values())

    def process(self, data):
        enum = list()
        miss = [
            "extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(2), value)",
            'return cls(value)'
        ]
        for code, name in data.items():
            code = f'0b{bin(code)[2:].zfill(2)}'
            renm = self.rename(name, code).upper()
            enum.append(f"{self.NAME}[{renm!r}] = {code}".ljust(76))
        return enum, miss


if __name__ == "__main__":
    SeedID()
