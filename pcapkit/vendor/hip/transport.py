# -*- coding: utf-8 -*-
"""HIP Transport Modes
=========================

.. module:: pcapkit.const.hip.transport

This module contains the vendor crawler for **HIP Transport Modes**,
which is automatically generating :class:`pcapkit.const.hip.transport.Transport`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Transport']


class Transport(Vendor):
    """HIP Transport Modes"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 3'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/transport-modes.csv'


if __name__ == '__main__':
    sys.exit(Transport())  # type: ignore[arg-type]
