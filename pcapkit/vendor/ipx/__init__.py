# -*- coding: utf-8 -*-
# pylint: disable=unused-import, wrong-import-position
""":class:`~pcapkit.protocols.internet.ipx.IPX` Vendor Crawlers
==================================================================

.. module:: pcapkit.vendor.ipx

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.ipx.IPX` implementations. Available
crawlers include:

.. list-table::

   * - :class:`IPX_Packet <pcapkit.vendor.ipx.packet.Packet>`
     - IPX Packet Types [*]_
   * - :class:`IPX_Socket <pcapkit.vendor.ipx.socket.Socket>`
     - IPX Socket Types [*]_

.. [*] https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#IPX_packet_structure
.. [*] https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#Socket_number

"""

###############################################################################
import sys

path = sys.path.pop(0)
###############################################################################

from pcapkit.vendor.ipx.packet import Packet as IPX_Packet
from pcapkit.vendor.ipx.socket import Socket as IPX_Socket

###############################################################################
sys.path.insert(0, path)
###############################################################################

__all__ = ['IPX_Packet', 'IPX_Socket']
