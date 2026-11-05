==============================================================================
:class:`~pcapkit.protocols.application.ssl.protocol.SSL` Constant Enumerations
==============================================================================

.. module:: pcapkit.const.tls

Shared by the record-layer implementations under
:class:`~pcapkit.protocols.application.ssl.protocol.SSL`:
:class:`~pcapkit.protocols.application.tls.protocol.TLS` (SSLv3 through TLS 1.3) and
:class:`~pcapkit.protocols.application.dtls.protocol.DTLS`.

.. list-table::

   * - :class:`TLS_ContentType <pcapkit.const.tls.content_type.ContentType>`
     - TLS/DTLS Content Types [*]_
   * - :class:`TLS_HandshakeType <pcapkit.const.tls.handshake_type.HandshakeType>`
     - TLS/DTLS HandshakeType [*]_
   * - :class:`TLS_ExtensionType <pcapkit.const.tls.extension_type.ExtensionType>`
     - TLS/DTLS ExtensionType Values [*]_

.. versionadded:: 1.6.0

TLS/DTLS Content Types
======================

.. module:: pcapkit.const.tls.content_type

Generated from :class:`pcapkit.vendor.tls.content_type.ContentType`.

.. autoclass:: pcapkit.const.tls.content_type.ContentType
   :members:
   :undoc-members:
   :show-inheritance:

TLS/DTLS HandshakeType
======================

.. module:: pcapkit.const.tls.handshake_type

Generated from :class:`pcapkit.vendor.tls.handshake_type.HandshakeType`, including
the DTLS-only messages :rfc:`9147#section-5.2` adds to the registry.

.. autoclass:: pcapkit.const.tls.handshake_type.HandshakeType
   :members:
   :undoc-members:
   :show-inheritance:

TLS/DTLS ExtensionType Values
=============================

.. module:: pcapkit.const.tls.extension_type

Generated from :class:`pcapkit.vendor.tls.extension_type.ExtensionType`.

.. autoclass:: pcapkit.const.tls.extension_type.ExtensionType
   :members:
   :undoc-members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
.. [*] https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
