# -*- coding: utf-8 -*-
"""HIP ECDSA Curve Label"""

from pcapkit.vendor.default import Vendor

__all__ = ['ECDSA_Curve']


class ECDSA_Curve(Vendor):
    """ECDSA Curve Label"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    LINK = 'https://www.iana.org/assignments/hip-parameters/ecdsa-curve-label.csv'


if __name__ == "__main__":
    ECDSA_Curve()
