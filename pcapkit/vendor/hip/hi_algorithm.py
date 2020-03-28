# -*- coding: utf-8 -*-
"""HIP HI Algorithm"""

from pcapkit.vendor.default import Vendor

__all__ = ['HI_Algorithm']


class HI_Algorithm(Vendor):
    """HI Algorithm"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    LINK = 'https://www.iana.org/assignments/hip-parameters/hi-algorithm.csv'


if __name__ == "__main__":
    HI_Algorithm()
