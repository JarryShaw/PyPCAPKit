# -*- coding: utf-8 -*-
# pylint: disable=unused-import,line-too-long
""":mod:`pcapkit.const.tls` Vendor Crawlers
==============================================

.. module:: pcapkit.vendor.tls

This module contains all vendor crawlers of the TLS/DTLS record-layer
constants. Available crawlers include:

.. list-table::

   * - :class:`TLS_ContentType <pcapkit.vendor.tls.content_type.ContentType>`
     - TLS/DTLS Content Types [*]_
   * - :class:`TLS_HandshakeType <pcapkit.vendor.tls.handshake_type.HandshakeType>`
     - TLS/DTLS HandshakeType [*]_
   * - :class:`TLS_ExtensionType <pcapkit.vendor.tls.extension_type.ExtensionType>`
     - TLS/DTLS ExtensionType Values [*]_
   * - :class:`TLS_ECPointFormat <pcapkit.vendor.tls.ec_point_format.ECPointFormat>`
     - TLS EC Point Formats [*]_
   * - :class:`TLS_CertificateStatusType <pcapkit.vendor.tls.certificate_status_type.CertificateStatusType>`
     - TLS Certificate Status Types [*]_
   * - :class:`TLS_PskKeyExchangeMode <pcapkit.vendor.tls.psk_key_exchange_mode.PskKeyExchangeMode>`
     - TLS PskKeyExchangeMode Values [*]_
   * - :class:`TLS_CertificateCompressionAlgorithm <pcapkit.vendor.tls.certificate_compression_algorithm.CertificateCompressionAlgorithm>`
     - TLS Certificate Compression Algorithm IDs [*]_
   * - :class:`TLS_HpkeKemId <pcapkit.vendor.tls.hpke_kem_id.HpkeKemId>`
     - HPKE KEM Identifiers [*]_
   * - :class:`TLS_HpkeKdfId <pcapkit.vendor.tls.hpke_kdf_id.HpkeKdfId>`
     - HPKE KDF Identifiers [*]_
   * - :class:`TLS_HpkeAeadId <pcapkit.vendor.tls.hpke_aead_id.HpkeAeadId>`
     - HPKE AEAD Identifiers [*]_

.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
.. [*] https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-9
.. [*] https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#certificate-status
.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-pskkeyexchangemode
.. [*] https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-certificate-compression-algorithm-ids
.. [*] https://www.iana.org/assignments/hpke/hpke.xhtml#hpke-kem-ids
.. [*] https://www.iana.org/assignments/hpke/hpke.xhtml#hpke-kdf-ids
.. [*] https://www.iana.org/assignments/hpke/hpke.xhtml#hpke-aead-ids

"""

from pcapkit.vendor.tls.certificate_compression_algorithm import \
    CertificateCompressionAlgorithm as TLS_CertificateCompressionAlgorithm
from pcapkit.vendor.tls.certificate_status_type import \
    CertificateStatusType as TLS_CertificateStatusType
from pcapkit.vendor.tls.content_type import ContentType as TLS_ContentType
from pcapkit.vendor.tls.ec_point_format import ECPointFormat as TLS_ECPointFormat
from pcapkit.vendor.tls.extension_type import ExtensionType as TLS_ExtensionType
from pcapkit.vendor.tls.handshake_type import HandshakeType as TLS_HandshakeType
from pcapkit.vendor.tls.hpke_aead_id import HpkeAeadId as TLS_HpkeAeadId
from pcapkit.vendor.tls.hpke_kdf_id import HpkeKdfId as TLS_HpkeKdfId
from pcapkit.vendor.tls.hpke_kem_id import HpkeKemId as TLS_HpkeKemId
from pcapkit.vendor.tls.psk_key_exchange_mode import PskKeyExchangeMode as TLS_PskKeyExchangeMode

__all__ = [
    'TLS_ContentType', 'TLS_HandshakeType', 'TLS_ExtensionType', 'TLS_ECPointFormat',
    'TLS_CertificateStatusType', 'TLS_PskKeyExchangeMode', 'TLS_CertificateCompressionAlgorithm',
    'TLS_HpkeKemId', 'TLS_HpkeKdfId', 'TLS_HpkeAeadId',
]
