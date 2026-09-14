# -*- coding: utf-8 -*-
"""SCTP Chunk Parameter Types
================================

.. module:: pcapkit.vendor.sctp.parameter

This module contains the vendor crawler for **SCTP Chunk Parameter Types**,
which is automatically generating :class:`pcapkit.const.sctp.parameter.Parameter`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Parameter']


class Parameter(Vendor):
    """SCTP Chunk Parameter Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/sctp-parameters/sctp-parameters-2.csv'


if __name__ == '__main__':
    sys.exit(Parameter())  # type: ignore[arg-type]
