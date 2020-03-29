# -*- coding: utf-8 -*-
"""OSPF Authentication Types"""

from pcapkit.vendor.default import Vendor

__all__ = ['Authentication']


class Authentication(Vendor):
    """Authentication Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ospf-authentication-codes/authentication-codes.csv'


if __name__ == "__main__":
    Authentication()
