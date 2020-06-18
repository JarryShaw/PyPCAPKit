# -*- coding: utf-8 -*-
"""IPv4 Classification Level Encodings"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['ClassificationLevel']

#: Encoding registry.
DATA = {
    0b0000_0001: 'Reserved [4]',
    0b0011_1101: 'Top Secret',
    0b0101_1010: 'Secret',
    0b1001_0110: 'Confidential',
    0b0110_0110: 'Reserved [3]',
    0b1100_1100: 'Reserved [2]',
    0b1010_1011: 'Unclassified',
    0b1111_0001: 'Reserved [1]',
}


def binary(code):
    """Convert code to binary form."""
    return f'0b{bin(code)[2:].upper().zfill(8)}'


class ClassificationLevel(Vendor):
    """Classification Level Encodings"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b00000000 <= value <= 0b11111111'

    def request(self):  # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Dict[int, str]: Registry data (:data:`~pcapkit.vendor.ipv4.classification_level.DATA`).

        """
        return DATA

    def count(self, data):
        """Count field records.

        Args:
            data (Dict[int, str]): Registry data.

        Returns:
            Counter: Field recordings.

        """
        return collections.Counter(map(self.safe_name, data.values()))  # pylint: disable=dict-values-not-iterating,map-builtin-not-iterating

    def process(self, data):
        """Process registry data.

        Args:
            data (Dict[int, str]): Registry data.

        Returns:
            List[str]: Enumeration fields.
            List[str]: Missing fields.

        """
        enum = list()
        miss = [
            'temp = bin(value)[2:].upper().zfill(8)',
            "extend_enum(cls, 'Unassigned_0b%s' % (temp[:4]+'_'+temp[4:]), value)",
            'return cls(value)'
        ]
        for code, name in data.items():
            code = binary(code)
            renm = self.rename(name, code)
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == "__main__":
    ClassificationLevel()
