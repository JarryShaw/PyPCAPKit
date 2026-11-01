# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":mod:`pcapkit.const.sslv2` Vendor Crawlers
================================================

.. module:: pcapkit.vendor.sslv2

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.application.sslv2.SSLv2` implementations.
Available crawlers include:

.. list-table::

   * - :class:`SSLv2_HandshakeType <pcapkit.vendor.sslv2.handshake_type.HandshakeType>`
     - SSLv2 Handshake Message Type
   * - :class:`SSLv2_Version <pcapkit.vendor.sslv2.version.Version>`
     - SSLv2 Protocol Version

"""

from pcapkit.vendor.sslv2.handshake_type import HandshakeType as SSLv2_HandshakeType
from pcapkit.vendor.sslv2.version import Version as SSLv2_Version

__all__ = ['SSLv2_HandshakeType', 'SSLv2_Version']
