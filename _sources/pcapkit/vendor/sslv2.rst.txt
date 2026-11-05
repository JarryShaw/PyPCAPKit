============================================================================
:class:`~pcapkit.protocols.application.sslv2.protocol.SSLv2` Vendor Crawlers
============================================================================

.. module:: pcapkit.vendor.sslv2

.. list-table::

   * - :class:`SSLv2_HandshakeType <pcapkit.vendor.sslv2.handshake_type.HandshakeType>`
     - SSLv2 Handshake Message Type [*]_
   * - :class:`SSLv2_Version <pcapkit.vendor.sslv2.version.Version>`
     - SSLv2 Protocol Version [*]_

.. versionadded:: 1.6.0

SSLv2 Handshake Message Type
============================

.. module:: pcapkit.vendor.sslv2.handshake_type

Generates :class:`pcapkit.const.sslv2.handshake_type.HandshakeType`.

.. note::

   This crawler does not crawl. Its source is the expired SSLv2 draft, not a
   live registry, so the data is maintained by hand in the ``DATA`` mapping of
   :mod:`pcapkit.vendor.sslv2.handshake_type`, and the class defines no
   ``LINK``.

.. autoclass:: pcapkit.vendor.sslv2.handshake_type.HandshakeType
   :members: FLAG
   :show-inheritance:

SSLv2 Protocol Version
======================

.. module:: pcapkit.vendor.sslv2.version

Generates :class:`pcapkit.const.sslv2.version.Version`.

.. note::

   This crawler does not crawl, for the same reason
   :class:`~pcapkit.vendor.sslv2.handshake_type.HandshakeType` does: the data
   is maintained by hand in the ``DATA`` mapping of
   :mod:`pcapkit.vendor.sslv2.version`, and the class defines no ``LINK``.

.. autoclass:: pcapkit.vendor.sslv2.version.Version
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://datatracker.ietf.org/doc/html/draft-hickman-netscape-ssl-00
.. [*] https://datatracker.ietf.org/doc/html/draft-hickman-netscape-ssl-00
