# -*- coding: utf-8 -*-
"""HIP Registration Types"""

from pcapkit.vendor.default import Vendor

__all__ = ['Registration']


class Registration(Vendor):
    """Registration Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-11.csv'


if __name__ == "__main__":
    Registration()
