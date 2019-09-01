# -*- coding: utf-8 -*-
"""HIP ECDSA_LOW Curve Label"""

from pcapkit.vendor.default import Vendor

__all__ = ['ECDSA_LOW_Curve']


class ECDSA_LOW_Curve(Vendor):
    """ECDSA_LOW Curve Label"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    LINK = 'https://www.iana.org/assignments/hip-parameters/ecdsa-low-curve-label.csv'


if __name__ == "__main__":
    ECDSA_LOW_Curve()
