# -*- coding: utf-8 -*-
"""Suite IDs
===============

.. module:: pcapkit.const.hip.suite

This module contains the vendor crawler for **Suite IDs**,
which is automatically generating :class:`pcapkit.const.hip.suite.Suite`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Suite']


class Suite(Vendor):
    """Suite IDs"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-6.csv'


if __name__ == '__main__':
    sys.exit(Suite())  # type: ignore[arg-type]
