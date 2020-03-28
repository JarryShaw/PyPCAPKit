# -*- coding: utf-8 -*-
"""HIP Certificate Types"""

from pcapkit.vendor.default import Vendor

__all__ = ['Certificate']


class Certificate(Vendor):
    """HIP Certificate Types"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    LINK = 'https://www.iana.org/assignments/hip-parameters/certificate-types.csv'


if __name__ == "__main__":
    Certificate()
