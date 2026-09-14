# -*- coding: utf-8 -*-
"""SCTP Chunk Types
======================

.. module:: pcapkit.vendor.sctp.chunk

This module contains the vendor crawler for **SCTP Chunk Types**,
which is automatically generating :class:`pcapkit.const.sctp.chunk.Chunk`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Chunk']


class Chunk(Vendor):
    """SCTP Chunk Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/sctp-parameters/sctp-parameters-1.csv'


if __name__ == '__main__':
    sys.exit(Chunk())  # type: ignore[arg-type]
