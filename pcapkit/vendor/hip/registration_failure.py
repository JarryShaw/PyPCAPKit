# -*- coding: utf-8 -*-
"""Registration Failure Types
================================

.. module:: pcapkit.const.hip.registration_failure

This module contains the vendor crawler for **Registration Failure Types**,
which is automatically generating :class:`pcapkit.const.hip.registration_failure.RegistrationFailure`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['RegistrationFailure']


class RegistrationFailure(Vendor):
    """Registration Failure Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-13.csv'


if __name__ == '__main__':
    sys.exit(RegistrationFailure())  # type: ignore[arg-type]
