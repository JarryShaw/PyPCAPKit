# -*- coding: utf-8 -*-
"""IEEE 802.11 Data Frame Subtypes
=====================================

.. module:: pcapkit.vendor.ieee802_11.data_subtype

This module contains the vendor crawler for **IEEE 802.11 Data Frame Subtypes**,
which is automatically generating :class:`pcapkit.const.ieee802_11.data_subtype.DataSubtype`.

The crawler reads :data:`DATA` rather than a URL, for the reason
:mod:`pcapkit.vendor.ieee802_11` gives. Table 9-1 marks the PCF subtypes
without QoS (Data with CF-Ack or CF-Poll, and their null forms) ``Reserved``,
so they resolve under that label, although the Linux kernel's
``include/linux/ieee80211.h`` and Wireshark's ``packet-ieee80211.c`` name them.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['DataSubtype']

#: Data frame (Type ``0b10``) Subtype values (IEEE Std 802.11-2020, Table 9-1).
#:
#: Maps a Subtype value to its *Subtype description*. A single ``Reserved``
#: row is a member, which :meth:`~Vendor.rename` suffixes with its value.
DATA = {
    0b0000: 'Data',
    0b0100: 'Null (no data)',
    0b1000: 'QoS Data',
    0b1001: 'QoS Data + CF-ACK',
    0b1010: 'QoS Data + CF-Poll',
    0b1011: 'QoS Data + CF-ACK + CF-Poll',
    0b1100: 'QoS Null (no data)',
    0b1101: 'Reserved',
    0b1110: 'QoS CF-Poll (no data)',
    0b1111: 'QoS CF-ACK + CF-Poll (no data)',
}  # type: dict[int, str]

#: Subtype ranges that Table 9-1 marks ``Reserved`` in one row, resolved by
#: ``_missing_`` under that bare label.
RESERVED = ((0b0001, 0b0011), (0b0101, 0b0111))  # type: tuple[tuple[int, int], ...]


class DataSubtype(Vendor):
    """IEEE 802.11 Data Frame Subtypes [IEEE Std 802.11-2020, Table 9-1]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0b0000 <= value <= 0b1111'

    def request(self) -> 'dict[int, str]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data
            (:data:`~pcapkit.vendor.ieee802_11.data_subtype.DATA`).

        """
        return DATA

    def count(self, data: 'dict[int, str]') -> 'Counter[str]':  # type: ignore[override]
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter(self.safe_name(name) for name in data.values())

    def process(self, data: 'dict[int, str]') -> 'tuple[list[str], list[str]]':  # type: ignore[override]
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = []  # type: list[str]

        for code, name in data.items():
            pval = str(code)
            renm = self.rename(name, pval)

            enum.append(f'#: {self.wrap_comment(name)}\n    {renm} = {pval}')

        for start, stop in RESERVED:
            miss.append(f'if {start} <= value <= {stop}:')
            miss.append('    #: Reserved')
            miss.append("    return cls._unregistered_member(value, 'Reserved')")
        return enum, miss


if __name__ == '__main__':
    sys.exit(DataSubtype())  # type: ignore[arg-type]
