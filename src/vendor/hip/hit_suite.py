# -*- coding: utf-8 -*-
"""HIP HIT Suite ID"""

from pcapkit.vendor.default import Vendor

__all__ = ['HIT_Suite']


class HIT_Suite(Vendor):
    """HIT Suite ID"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 15'
    LINK = 'https://www.iana.org/assignments/hip-parameters/hit-suite-id.csv'


if __name__ == "__main__":
    HIT_Suite()
