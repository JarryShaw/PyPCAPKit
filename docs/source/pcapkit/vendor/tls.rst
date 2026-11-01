===============================================================
:class:`~pcapkit.protocols.application.ssl.SSL` Vendor Crawlers
===============================================================

.. module:: pcapkit.vendor.tls

This module contains the vendor crawlers of the constant enumerations shared by
the record-layer implementations under the
:class:`~pcapkit.protocols.application.ssl.SSL` umbrella --
:class:`~pcapkit.protocols.application.tls.TLS` (SSLv3 through TLS 1.3) and
:class:`~pcapkit.protocols.application.dtls.DTLS`. Available vendor crawlers
include:

.. list-table::

   * - :class:`TLS_ContentType <pcapkit.vendor.tls.content_type.ContentType>`
     - TLS/DTLS Content Types [*]_
   * - :class:`TLS_HandshakeType <pcapkit.vendor.tls.handshake_type.HandshakeType>`
     - TLS/DTLS HandshakeType [*]_

.. versionadded:: 1.6.0

TLS/DTLS Content Types
======================

.. module:: pcapkit.vendor.tls.content_type

This module contains the vendor crawler for **TLS/DTLS Content Types**,
which is automatically generating :class:`pcapkit.const.tls.content_type.ContentType`.

.. autoclass:: pcapkit.vendor.tls.content_type.ContentType
   :members: FLAG, LINK
   :show-inheritance:

TLS/DTLS HandshakeType
======================

.. module:: pcapkit.vendor.tls.handshake_type

This module contains the vendor crawler for **TLS/DTLS HandshakeType**,
which is automatically generating :class:`pcapkit.const.tls.handshake_type.HandshakeType`.

.. autoclass:: pcapkit.vendor.tls.handshake_type.HandshakeType
   :members: FLAG, LINK
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
