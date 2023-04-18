# -*- coding: utf-8 -*-
"""ECDSA_LOW Curve Label
===========================

.. module:: pcapkit.const.hip.ecdsa_low_curve

This module contains the vendor crawler for **ECDSA_LOW Curve Label**,
which is automatically generating :class:`pcapkit.const.hip.ecdsa_low_curve.ECDSALowCurve`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['ECDSALowCurve']


class ECDSALowCurve(Vendor):
    """ECDSA_LOW Curve Label"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/ecdsa-low-curve-label.csv'


if __name__ == '__main__':
    sys.exit(ECDSALowCurve())  # type: ignore[arg-type]
