# -*- coding: utf-8 -*-
"""Authentication Types
==========================

.. module:: pcapkit.vendor.ospf.authentication

This module contains the vendor crawler for **Authentication Types**,
which is automatically generating :class:`pcapkit.const.ospf.authentication.Authentication`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Authentication']


class Authentication(Vendor):
    """Authentication Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ospf-authentication-codes/authentication-codes.csv'


if __name__ == '__main__':
    sys.exit(Authentication())  # type: ignore[arg-type]
