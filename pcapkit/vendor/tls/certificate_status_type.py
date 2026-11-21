# -*- coding: utf-8 -*-
"""TLS Certificate Status Types
==================================

.. module:: pcapkit.vendor.tls.certificate_status_type

This module contains the vendor crawler for **TLS Certificate Status Types**,
which is automatically generating
:class:`pcapkit.const.tls.certificate_status_type.CertificateStatusType`.

The registry is IANA's ``TLS Certificate Status Types`` table, a four-column CSV --
``Value, Description, Reference, Comment``. Its rows are the ``status_type`` a
``status_request`` extension carries (:rfc:`6066#section-8`); see
:mod:`pcapkit.vendor.tls.ec_point_format` for how a row becomes a member.

"""

import sys

from pcapkit.vendor.tls.ec_point_format import ECPointFormat

__all__ = ['CertificateStatusType']


class CertificateStatusType(ECPointFormat):
    """TLS Certificate Status Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/tls-extensiontype-values/certificate-status.csv'

    #: Column of the ``Reference`` cell.
    REFERENCE = 2
    #: Column of the ``Comment`` cell.
    COMMENT = 3


if __name__ == '__main__':
    sys.exit(CertificateStatusType())  # type: ignore[arg-type]
