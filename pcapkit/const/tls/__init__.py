# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.ssl.SSL` Constant Enumerations
==========================================================================

.. module:: pcapkit.const.tls

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.ssl.SSL` implementations -- i.e.
:class:`~pcapkit.protocols.application.tls.TLS` and
:class:`~pcapkit.protocols.application.dtls.DTLS`. Available enumerations
include:

.. list-table::

   * - :class:`TLS_ContentType <pcapkit.const.tls.content_type.ContentType>`
     - TLS/DTLS Content Types [*]_
   * - :class:`TLS_HandshakeType <pcapkit.const.tls.handshake_type.HandshakeType>`
     - TLS/DTLS HandshakeType [*]_

.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7

"""

from pcapkit.const.tls.content_type import ContentType as TLS_ContentType
from pcapkit.const.tls.handshake_type import HandshakeType as TLS_HandshakeType

__all__ = ['TLS_ContentType', 'TLS_HandshakeType']
