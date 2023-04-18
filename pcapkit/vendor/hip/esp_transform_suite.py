# -*- coding: utf-8 -*-
"""ESP Transform Suite IDs
=============================

.. module:: pcapkit.const.hip.esp_transform_suite

This module contains the vendor crawler for **ESP Transform Suite IDs**,
which is automatically generating :class:`pcapkit.const.hip.esp_transform_suite.ESPTransformSuite`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['ESPTransformSuite']


class ESPTransformSuite(Vendor):
    """ESP Transform Suite IDs"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/esp-transform-suite-ids.csv'


if __name__ == '__main__':
    sys.exit(ESPTransformSuite())  # type: ignore[arg-type]
