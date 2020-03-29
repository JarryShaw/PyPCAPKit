# -*- coding: utf-8 -*-
"""HIP HIT Suite ID"""

from pcapkit.vendor.default import Vendor

__all__ = ['HITSuite']


class HITSuite(Vendor):
    """HIT Suite ID"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 15'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hit-suite-id.csv'


if __name__ == "__main__":
    HITSuite()
