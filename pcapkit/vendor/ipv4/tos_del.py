# -*- coding: utf-8 -*-
"""IPv4 TOS (DS Field) Delay"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['TOS_DEL']

DATA = {
    0: 'Normal',
    1: 'Low',
}


class TOS_DEL(Vendor):
    """TOS (DS Field) Delay"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 1'

    def request(self):  # pylint: disable=arguments-differ
        return DATA

    def count(self, data):
        return collections.Counter(data.values())

    def process(self, data):
        enum = list()
        miss = [
            "extend_enum(cls, 'Unassigned [%d]' % value, value)",
            'return cls(value)'
        ]
        for code, name in DATA.items():
            renm = self.rename(name, code).upper()
            enum.append("{}[{!r}] = {}".format(self.NAME, renm, code).ljust(76))
        return enum, miss


if __name__ == "__main__":
    TOS_DEL()
