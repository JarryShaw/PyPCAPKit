# -*- coding: utf-8 -*-
"""HIP NAT Traversal Modes
=============================

.. module:: pcapkit.const.hip.nat_traversal

This module contains the vendor crawler for **HIP NAT Traversal Modes**,
which is automatically generating :class:`pcapkit.const.hip.nat_traversal.NATTraversal`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['NATTraversal']


class NATTraversal(Vendor):
    """HIP NAT Traversal Modes"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/nat-traversal.csv'


if __name__ == '__main__':
    sys.exit(NATTraversal())  # type: ignore[arg-type]
