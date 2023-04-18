# -*- coding: utf-8 -*-
"""HIP Certificate Types
===========================

.. module:: pcapkit.const.hip.certificate

This module contains the vendor crawler for **HIP Certificate Types**,
which is automatically generating :class:`pcapkit.const.hip.certificate.Certificate`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Certificate']


class Certificate(Vendor):
    """HIP Certificate Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/certificate-types.csv'


if __name__ == '__main__':
    sys.exit(Certificate())  # type: ignore[arg-type]
