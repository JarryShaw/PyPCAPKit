# -*- coding: utf-8 -*-
"""OSPF Packet Types"""

from pcapkit.vendor.default import Vendor

__all__ = ['Packet']


class Packet(Vendor):
    """OSPF Packet Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters-3.csv'


if __name__ == "__main__":
    Packet()
