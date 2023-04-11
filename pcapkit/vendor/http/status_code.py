# -*- coding: utf-8 -*-
"""HTTP Status Code
======================

This module contains the vendor crawler for **HTTP Status Code**,
which is automatically generating :class:`pcapkit.const.http.status_code.StatusCode`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['StatusCode']


class StatusCode(Vendor):
    """HTTP Status Code"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 100 <= value <= 599'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/http-status-codes/http-status-codes-1.csv'


if __name__ == '__main__':
    sys.exit(StatusCode())  # type: ignore[arg-type]
