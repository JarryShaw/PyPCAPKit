# -*- coding: utf-8 -*-
"""DCCP Drop Codes
==================

.. module:: pcapkit.vendor.dccp.drop_code

This module contains the vendor crawler for **DCCP Drop Codes**,
which is automatically generating :class:`pcapkit.const.dccp.drop_code.DropCode`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['DropCode']


class DropCode(Vendor):
    """DCCP Drop Codes"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 7'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/dccp-parameters/dccp-parameters-11.csv'


if __name__ == '__main__':
    sys.exit(DropCode())  # type: ignore[arg-type]
