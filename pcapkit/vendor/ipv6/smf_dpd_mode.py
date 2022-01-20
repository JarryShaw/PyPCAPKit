# -*- coding: utf-8 -*-
"""IPv6 Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options"""

import collections

from pcapkit.vendor.default import Vendor

__all__ = ['SMFDPDMode']

#: QS function registry.
DATA = {
    0:  'I-DPD',
    1:  'H-DPD',
}


class SMFDPDMode(Vendor):
    """Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 1'

    def request(self):  # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Dict[int, str]: Registry data (:data:`~pcapkit.vendor.ipv6.smf_dpd_mode.DATA`).

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
            "extend_enum(cls, 'Unassigned_%d' % value, value)",
            'return cls(value)'
        ]
        for code, name in DATA.items():
            renm = self.rename(name, code)
            enum.append(f"{renm} = {code}".ljust(76))
        return enum, miss


if __name__ == "__main__":
    SMFDPDMode()
