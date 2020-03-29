# -*- coding: utf-8 -*-
"""HIP HI Algorithm"""

from pcapkit.vendor.default import Vendor

__all__ = ['HIAlgorithm']


class HIAlgorithm(Vendor):
    """HI Algorithm"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hi-algorithm.csv'


if __name__ == "__main__":
    HIAlgorithm()
