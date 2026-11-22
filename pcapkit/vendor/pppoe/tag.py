# -*- coding: utf-8 -*-
"""PPPoE TAG Values
======================

.. module:: pcapkit.vendor.pppoe.tag

This module contains the vendor crawler for **PPPoE TAG Values**,
which is automatically generating :class:`pcapkit.const.pppoe.tag.Tag`.

"""

import sys

from pcapkit.vendor.pppoe.code import Code

__all__ = ['Tag']


class Tag(Code):
    """PPPoE TAG Values"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/pppoe-parameters/pppoe-parameters-1.csv'
    #: Digits of a value in hex form.
    WIDTH = 4


if __name__ == '__main__':
    sys.exit(Tag())  # type: ignore[arg-type]
