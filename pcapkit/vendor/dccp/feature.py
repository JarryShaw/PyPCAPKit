# -*- coding: utf-8 -*-
"""DCCP Feature Numbers
=======================

.. module:: pcapkit.vendor.dccp.feature

This module contains the vendor crawler for **DCCP Feature Numbers**,
which is automatically generating :class:`pcapkit.const.dccp.feature.Feature`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Feature']


class Feature(Vendor):
    """DCCP Feature Numbers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/dccp-parameters/dccp-parameters-7.csv'


if __name__ == '__main__':
    sys.exit(Feature())  # type: ignore[arg-type]
