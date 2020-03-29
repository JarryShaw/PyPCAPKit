# -*- coding: utf-8 -*-
"""HIP Registration Failure Types"""

from pcapkit.vendor.default import Vendor

__all__ = ['RegistrationFailure']


class RegistrationFailure(Vendor):
    """Registration Failure Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-13.csv'


if __name__ == "__main__":
    RegistrationFailure()
