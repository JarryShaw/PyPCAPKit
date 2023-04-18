# -*- coding: utf-8 -*-
"""Registration Types
========================

.. module:: pcapkit.const.hip.registration

This module contains the vendor crawler for **Registration Types**,
which is automatically generating :class:`pcapkit.const.hip.registration.Registration`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Registration']


class Registration(Vendor):
    """Registration Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-11.csv'


if __name__ == '__main__':
    sys.exit(Registration())  # type: ignore[arg-type]
