# -*- coding: utf-8 -*-
"""HIP ECDSA_LOW Curve Label"""

from pcapkit.vendor.default import Vendor

__all__ = ['ECDSA_LOWCurve']


class ECDSA_LOWCurve(Vendor):
    """ECDSA_LOW Curve Label"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/ecdsa-low-curve-label.csv'


if __name__ == "__main__":
    ECDSA_LOWCurve()
