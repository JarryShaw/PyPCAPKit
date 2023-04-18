# -*- coding: utf-8 -*-
"""ECDSA Curve Label
=======================

.. module:: pcapkit.const.hip.ecdsa_curve

This module contains the vendor crawler for **ECDSA Curve Label**,
which is automatically generating :class:`pcapkit.const.hip.ecdsa_curve.ECDSACurve`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['ECDSACurve']


class ECDSACurve(Vendor):
    """ECDSA Curve Label"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/ecdsa-curve-label.csv'


if __name__ == '__main__':
    sys.exit(ECDSACurve())  # type: ignore[arg-type]
