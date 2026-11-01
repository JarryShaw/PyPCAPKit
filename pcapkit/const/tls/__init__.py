# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.ssl.SSL` Constant Enumerations
==========================================================================

.. module:: pcapkit.const.tls

This module contains the constant enumerations shared by the record-layer
implementations under the :class:`~pcapkit.protocols.application.ssl.SSL`
umbrella -- :class:`~pcapkit.protocols.application.tls.TLS` (SSLv3 through
TLS 1.3) and :class:`~pcapkit.protocols.application.dtls.DTLS`. Available
enumerations include:

.. list-table::

   * - :class:`TLS_ContentType <pcapkit.const.tls.content_type.ContentType>`
     - TLS/DTLS Content Types [*]_
   * - :class:`TLS_HandshakeType <pcapkit.const.tls.handshake_type.HandshakeType>`
     - TLS/DTLS HandshakeType [*]_
   * - :class:`TLS_ExtensionType <pcapkit.const.tls.extension_type.ExtensionType>`
     - TLS/DTLS ExtensionType Values [*]_

.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
.. [*] https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1

"""

from pcapkit.const.tls.content_type import ContentType as TLS_ContentType
from pcapkit.const.tls.extension_type import ExtensionType as TLS_ExtensionType
from pcapkit.const.tls.handshake_type import HandshakeType as TLS_HandshakeType

__all__ = ['TLS_ContentType', 'TLS_HandshakeType', 'TLS_ExtensionType']
