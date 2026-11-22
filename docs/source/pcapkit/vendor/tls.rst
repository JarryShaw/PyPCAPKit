========================================================================
:class:`~pcapkit.protocols.application.ssl.protocol.SSL` Vendor Crawlers
========================================================================

.. module:: pcapkit.vendor.tls

For the constant enumerations shared by the record-layer implementations under
:class:`~pcapkit.protocols.application.ssl.protocol.SSL`:
:class:`~pcapkit.protocols.application.tls.protocol.TLS` (SSLv3 through TLS 1.3) and
:class:`~pcapkit.protocols.application.dtls.protocol.DTLS`.

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

.. versionadded:: 1.6.0

TLS/DTLS Content Types
======================

.. module:: pcapkit.vendor.tls.content_type

Generates :class:`pcapkit.const.tls.content_type.ContentType`.

.. autoclass:: pcapkit.vendor.tls.content_type.ContentType
   :members: FLAG, LINK
   :show-inheritance:

TLS/DTLS HandshakeType
======================

.. module:: pcapkit.vendor.tls.handshake_type

Generates :class:`pcapkit.const.tls.handshake_type.HandshakeType`.

.. autoclass:: pcapkit.vendor.tls.handshake_type.HandshakeType
   :members: FLAG, LINK
   :show-inheritance:

TLS/DTLS ExtensionType Values
=============================

.. module:: pcapkit.vendor.tls.extension_type

Generates :class:`pcapkit.const.tls.extension_type.ExtensionType`.

.. autoclass:: pcapkit.vendor.tls.extension_type.ExtensionType
   :members: FLAG, LINK
   :show-inheritance:

TLS EC Point Formats
====================

.. module:: pcapkit.vendor.tls.ec_point_format

Generates :class:`pcapkit.const.tls.ec_point_format.ECPointFormat`.

.. autoclass:: pcapkit.vendor.tls.ec_point_format.ECPointFormat
   :members: FLAG, LINK, REFERENCE, COMMENT
   :show-inheritance:

TLS Certificate Status Types
============================

.. module:: pcapkit.vendor.tls.certificate_status_type

Generates :class:`pcapkit.const.tls.certificate_status_type.CertificateStatusType`.

.. autoclass:: pcapkit.vendor.tls.certificate_status_type.CertificateStatusType
   :members: FLAG, LINK, REFERENCE, COMMENT
   :show-inheritance:

TLS PskKeyExchangeMode Values
=============================

.. module:: pcapkit.vendor.tls.psk_key_exchange_mode

Generates :class:`pcapkit.const.tls.psk_key_exchange_mode.PskKeyExchangeMode`.

.. autoclass:: pcapkit.vendor.tls.psk_key_exchange_mode.PskKeyExchangeMode
   :members: FLAG, LINK, REFERENCE, COMMENT
   :show-inheritance:

TLS Certificate Compression Algorithm IDs
=========================================

.. module:: pcapkit.vendor.tls.certificate_compression_algorithm

Generates :class:`pcapkit.const.tls.certificate_compression_algorithm.CertificateCompressionAlgorithm`.

.. autoclass:: pcapkit.vendor.tls.certificate_compression_algorithm.CertificateCompressionAlgorithm
   :members: FLAG, LINK, REFERENCE, COMMENT
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
.. [*] https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-9
.. [*] https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#certificate-status
.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-pskkeyexchangemode
.. [*] https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-certificate-compression-algorithm-ids
