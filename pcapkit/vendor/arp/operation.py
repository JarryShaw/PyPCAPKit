# -*- coding: utf-8 -*-
"""ARP Operation Codes [:rfc:`826`][:rfc:`5494`]"""

from pcapkit.vendor.default import Vendor

__all__ = ['Operation']


class Operation(Vendor):
    """Operation Codes [:rfc:`826`][:rfc:`5494`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/arp-parameters/arp-parameters-1.csv'


if __name__ == "__main__":
    Operation()
