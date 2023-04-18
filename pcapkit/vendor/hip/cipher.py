# -*- coding: utf-8 -*-
"""Cipher IDs
================

.. module:: pcapkit.const.hip.cipher

This module contains the vendor crawler for **Cipher IDs**,
which is automatically generating :class:`pcapkit.const.hip.cipher.Cipher`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Cipher']


class Cipher(Vendor):
    """Cipher IDs"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-cipher-id.csv'


if __name__ == '__main__':
    sys.exit(Cipher())  # type: ignore[arg-type]
