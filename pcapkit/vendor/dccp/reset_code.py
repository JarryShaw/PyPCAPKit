# -*- coding: utf-8 -*-
"""DCCP Reset Codes
===================

.. module:: pcapkit.vendor.dccp.reset_code

This module contains the vendor crawler for **DCCP Reset Codes**,
which is automatically generating :class:`pcapkit.const.dccp.reset_code.ResetCode`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['ResetCode']


class ResetCode(Vendor):
    """DCCP Reset Codes"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/dccp-parameters/dccp-parameters-3.csv'


if __name__ == '__main__':
    sys.exit(ResetCode())  # type: ignore[arg-type]
