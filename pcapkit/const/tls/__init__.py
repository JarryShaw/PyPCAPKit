# -*- coding: utf-8 -*-
# pylint: disable=unused-import,line-too-long
""":class:`~pcapkit.protocols.application.ssl.protocol.SSL` Constant Enumerations
====================================================================================

.. module:: pcapkit.const.tls

This module contains the constant enumerations shared by the record-layer
implementations under the :class:`~pcapkit.protocols.application.ssl.protocol.SSL`
umbrella -- :class:`~pcapkit.protocols.application.tls.protocol.TLS` (SSLv3 through
TLS 1.3) and :class:`~pcapkit.protocols.application.dtls.protocol.DTLS`. Available
enumerations include:

.. list-table::

   * - :class:`TLS_ContentType <pcapkit.const.tls.content_type.ContentType>`
     - TLS/DTLS Content Types [*]_
   * - :class:`TLS_HandshakeType <pcapkit.const.tls.handshake_type.HandshakeType>`
     - TLS/DTLS HandshakeType [*]_
   * - :class:`TLS_ExtensionType <pcapkit.const.tls.extension_type.ExtensionType>`
     - TLS/DTLS ExtensionType Values [*]_
   * - :class:`TLS_ECPointFormat <pcapkit.const.tls.ec_point_format.ECPointFormat>`
     - TLS EC Point Formats [*]_
   * - :class:`TLS_CertificateStatusType <pcapkit.const.tls.certificate_status_type.CertificateStatusType>`
     - TLS Certificate Status Types [*]_
   * - :class:`TLS_PskKeyExchangeMode <pcapkit.const.tls.psk_key_exchange_mode.PskKeyExchangeMode>`
     - TLS PskKeyExchangeMode Values [*]_
   * - :class:`TLS_CertificateCompressionAlgorithm <pcapkit.const.tls.certificate_compression_algorithm.CertificateCompressionAlgorithm>`
     - TLS Certificate Compression Algorithm IDs [*]_
   * - :class:`TLS_HpkeKemId <pcapkit.const.tls.hpke_kem_id.HpkeKemId>`
     - HPKE KEM Identifiers [*]_
   * - :class:`TLS_HpkeKdfId <pcapkit.const.tls.hpke_kdf_id.HpkeKdfId>`
     - HPKE KDF Identifiers [*]_
   * - :class:`TLS_HpkeAeadId <pcapkit.const.tls.hpke_aead_id.HpkeAeadId>`
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

from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.tls.certificate_compression_algorithm import \
        CertificateCompressionAlgorithm as TLS_CertificateCompressionAlgorithm
    from pcapkit.const.tls.certificate_status_type import \
        CertificateStatusType as TLS_CertificateStatusType
    from pcapkit.const.tls.content_type import ContentType as TLS_ContentType
    from pcapkit.const.tls.ec_point_format import ECPointFormat as TLS_ECPointFormat
    from pcapkit.const.tls.extension_type import ExtensionType as TLS_ExtensionType
    from pcapkit.const.tls.handshake_type import HandshakeType as TLS_HandshakeType
    from pcapkit.const.tls.hpke_aead_id import HpkeAeadId as TLS_HpkeAeadId
    from pcapkit.const.tls.hpke_kdf_id import HpkeKdfId as TLS_HpkeKdfId
    from pcapkit.const.tls.hpke_kem_id import HpkeKemId as TLS_HpkeKemId
    from pcapkit.const.tls.psk_key_exchange_mode import PskKeyExchangeMode as TLS_PskKeyExchangeMode

__all__ = [
    'TLS_ContentType', 'TLS_HandshakeType', 'TLS_ExtensionType', 'TLS_ECPointFormat',
    'TLS_CertificateStatusType', 'TLS_PskKeyExchangeMode', 'TLS_CertificateCompressionAlgorithm',
    'TLS_HpkeKemId', 'TLS_HpkeKdfId', 'TLS_HpkeAeadId',
]

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'TLS_ContentType': ('content_type', 'ContentType'),
    'TLS_HandshakeType': ('handshake_type', 'HandshakeType'),
    'TLS_ExtensionType': ('extension_type', 'ExtensionType'),
    'TLS_ECPointFormat': ('ec_point_format', 'ECPointFormat'),
    'TLS_CertificateStatusType': ('certificate_status_type', 'CertificateStatusType'),
    'TLS_PskKeyExchangeMode': ('psk_key_exchange_mode', 'PskKeyExchangeMode'),
    'TLS_CertificateCompressionAlgorithm': ('certificate_compression_algorithm', 'CertificateCompressionAlgorithm'),
    'TLS_HpkeKemId': ('hpke_kem_id', 'HpkeKemId'),
    'TLS_HpkeKdfId': ('hpke_kdf_id', 'HpkeKdfId'),
    'TLS_HpkeAeadId': ('hpke_aead_id', 'HpkeAeadId'),
})
