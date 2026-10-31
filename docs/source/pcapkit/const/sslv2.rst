=========================================================================
:class:`~pcapkit.protocols.application.sslv2.SSLv2` Constant Enumerations
=========================================================================

.. module:: pcapkit.const.sslv2

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.sslv2.SSLv2` implementations. Available
enumerations include:

.. list-table::

   * - :class:`SSLv2_HandshakeType <pcapkit.const.sslv2.handshake_type.HandshakeType>`
     - SSLv2 Handshake Message Type [*]_
   * - :class:`SSLv2_Version <pcapkit.const.sslv2.version.Version>`
     - SSLv2 Protocol Version [*]_

.. versionadded:: 1.6.0

SSLv2 Handshake Message Type
=============================

.. module:: pcapkit.const.sslv2.handshake_type

This module contains the constant enumeration for **SSLv2 Handshake Message
Type**, which is automatically generated from
:class:`pcapkit.vendor.sslv2.handshake_type.HandshakeType`. Its source is the
expired SSLv2 draft linked above, not a live registry, so the crawler reads a
``DATA`` attribute instead of fetching a URL.

.. autoclass:: pcapkit.const.sslv2.handshake_type.HandshakeType
   :members:
   :undoc-members:
   :show-inheritance:

SSLv2 Protocol Version
=======================

.. module:: pcapkit.const.sslv2.version

This module contains the constant enumeration for **SSLv2 Protocol
Version**, which is automatically generated from
:class:`pcapkit.vendor.sslv2.version.Version`, for the same reason
:class:`~pcapkit.const.sslv2.handshake_type.HandshakeType` is.

.. autoclass:: pcapkit.const.sslv2.version.Version
   :members:
   :undoc-members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://datatracker.ietf.org/doc/html/draft-hickman-netscape-ssl-00
.. [*] https://datatracker.ietf.org/doc/html/draft-hickman-netscape-ssl-00
