# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.ipx.IPX` Constant Enumerations
========================================================================

.. module:: pcapkit.const.ipx

This module contains all constant enumerations of
:class:`~pcapkit.protocols.internet.ipx.IPX` implementations. Available
enumerations include:

.. list-table::

   * - :class:`IPX_Packet <pcapkit.const.ipx.packet.Packet>`
     - IPX Packet Types [*]_
   * - :class:`IPX_Socket <pcapkit.const.ipx.socket.Socket>`
     - IPX Socket Types [*]_

.. [*] https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#IPX_packet_structure
.. [*] https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#Socket_number

"""

from pcapkit.const.ipx.packet import Packet as IPX_Packet
from pcapkit.const.ipx.socket import Socket as IPX_Socket

__all__ = ['IPX_Packet', 'IPX_Socket']
