# -*- coding: utf-8 -*-
"""DI-Types
==============

.. module:: pcapkit.const.hip.di

This module contains the vendor crawler for **DI-Types**,
which is automatically generating :class:`pcapkit.const.hip.di.DITypes`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['DITypes']


class DITypes(Vendor):
    """DI-Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 15'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-7.csv'


if __name__ == '__main__':
    sys.exit(DITypes())  # type: ignore[arg-type]
