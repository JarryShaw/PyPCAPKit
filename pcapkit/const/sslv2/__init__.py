# -*- coding: utf-8 -*-
# pylint: disable=unused-import
r""":class:`~pcapkit.protocols.application.sslv2.SSLv2` Constant Enumerations
=============================================================================

.. module:: pcapkit.const.sslv2

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.sslv2.SSLv2` implementations. Available
enumerations include:

.. list-table::

   * - :class:`SSLv2_HandshakeType <pcapkit.const.sslv2.handshake_type.HandshakeType>`
     - SSLv2 Handshake Message Type [*]_
   * - :class:`SSLv2_Version <pcapkit.const.sslv2.version.Version>`
     - SSLv2 Protocol Version [*]_

.. [*] https://datatracker.ietf.org/doc/html/draft-hickman-netscape-ssl-00
.. [*] https://datatracker.ietf.org/doc/html/draft-hickman-netscape-ssl-00

"""

from pcapkit.const.sslv2.handshake_type import HandshakeType as SSLv2_HandshakeType
from pcapkit.const.sslv2.version import Version as SSLv2_Version

__all__ = ['SSLv2_HandshakeType', 'SSLv2_Version']
