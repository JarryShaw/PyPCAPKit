# -*- coding: utf-8 -*-
"""HIT Suite ID
==================

.. module:: pcapkit.const.hip.hit_suite

This module contains the vendor crawler for **HIT Suite ID**,
which is automatically generating :class:`pcapkit.const.hip.hit_suite.HITSuite`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['HITSuite']


class HITSuite(Vendor):
    """HIT Suite ID"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 15'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hit-suite-id.csv'


if __name__ == '__main__':
    sys.exit(HITSuite())  # type: ignore[arg-type]
