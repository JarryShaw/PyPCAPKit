# -*- coding: utf-8 -*-
"""HI Algorithm
==================

.. module:: pcapkit.const.hip.hi_algorithm

This module contains the vendor crawler for **HI Algorithm**,
which is automatically generating :class:`pcapkit.const.hip.hi_algorithm.HIAlgorithm`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['HIAlgorithm']


class HIAlgorithm(Vendor):
    """HI Algorithm"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hi-algorithm.csv'


if __name__ == '__main__':
    sys.exit(HIAlgorithm())  # type: ignore[arg-type]
