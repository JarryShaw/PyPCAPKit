# -*- coding: utf-8 -*-
"""SCTP Error Cause Codes
============================

.. module:: pcapkit.vendor.sctp.cause_code

This module contains the vendor crawler for **SCTP Error Cause Codes**,
which is automatically generating :class:`pcapkit.const.sctp.cause_code.CauseCode`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['CauseCode']


class CauseCode(Vendor):
    """SCTP Error Cause Codes"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/sctp-parameters/sctp-parameters-24.csv'


if __name__ == '__main__':
    sys.exit(CauseCode())  # type: ignore[arg-type]
