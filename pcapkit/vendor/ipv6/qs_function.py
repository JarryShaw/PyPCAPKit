# -*- coding: utf-8 -*-
"""IPv6 QS Functions"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['QS_Function']

DATA = {
    0:  'Quick-Start Request',
    8:  'Report of Approved Rate',
}


class QS_Function(Vendor):
    """QS Functions"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 8'

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
            renm = self.rename(name, code)
            enum.append(f"{self.NAME}[{renm!r}] = {code}".ljust(76))
        return enum, miss


if __name__ == "__main__":
    QS_Function()
