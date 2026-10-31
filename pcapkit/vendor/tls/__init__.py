# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":mod:`pcapkit.const.tls` Vendor Crawlers
=============================================

.. module:: pcapkit.vendor.tls

This module contains all vendor crawlers of the TLS/DTLS record-layer
constants. Available crawlers include:

.. list-table::

   * - :class:`TLS_ContentType <pcapkit.vendor.tls.content_type.ContentType>`
     - TLS/DTLS Content Types [*]_
   * - :class:`TLS_HandshakeType <pcapkit.vendor.tls.handshake_type.HandshakeType>`
     - TLS/DTLS HandshakeType [*]_

.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7

"""

from pcapkit.vendor.tls.content_type import ContentType as TLS_ContentType
from pcapkit.vendor.tls.handshake_type import HandshakeType as TLS_HandshakeType

__all__ = ['TLS_ContentType', 'TLS_HandshakeType']
