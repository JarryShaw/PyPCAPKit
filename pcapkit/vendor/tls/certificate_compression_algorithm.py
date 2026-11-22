# -*- coding: utf-8 -*-
"""TLS Certificate Compression Algorithm IDs
===============================================

.. module:: pcapkit.vendor.tls.certificate_compression_algorithm

This module contains the vendor crawler for **TLS Certificate Compression Algorithm IDs**,
which is automatically generating
:class:`pcapkit.const.tls.certificate_compression_algorithm.CertificateCompressionAlgorithm`.

The registry is IANA's ``TLS Certificate Compression Algorithm IDs`` table, a
four-column CSV -- ``Algorithm Number, Description, Reference, Comment``. Its rows
are the values a ``compress_certificate`` extension lists (:rfc:`8879#section-3`);
see :mod:`pcapkit.vendor.tls.ec_point_format` for how a row becomes a member.

"""

import sys

from pcapkit.vendor.tls.ec_point_format import ECPointFormat

__all__ = ['CertificateCompressionAlgorithm']


class CertificateCompressionAlgorithm(ECPointFormat):
    """TLS Certificate Compression Algorithm IDs"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/tls-extensiontype-values/tls-certificate-compression-algorithm-ids.csv'

    #: Column of the ``Reference`` cell.
    REFERENCE = 2
    #: Column of the ``Comment`` cell.
    COMMENT = 3


if __name__ == '__main__':
    sys.exit(CertificateCompressionAlgorithm())  # type: ignore[arg-type]
