# -*- coding: utf-8 -*-
"""DCCP Option Types
====================

.. module:: pcapkit.vendor.dccp.option

This module contains the vendor crawler for **DCCP Option Types**,
which is automatically generating :class:`pcapkit.const.dccp.option.Option`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Option']


class Option(Vendor):
    """DCCP Option Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/dccp-parameters/dccp-parameters-5.csv'


if __name__ == '__main__':
    sys.exit(Option())  # type: ignore[arg-type]
