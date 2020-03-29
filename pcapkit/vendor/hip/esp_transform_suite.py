# -*- coding: utf-8 -*-
"""HIP ESP Transform Suite IDs"""

from pcapkit.vendor.default import Vendor

__all__ = ['ESPTransformSuite']


class ESPTransformSuite(Vendor):
    """ESP Transform Suite IDs"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/esp-transform-suite-ids.csv'


if __name__ == "__main__":
    ESPTransformSuite()
