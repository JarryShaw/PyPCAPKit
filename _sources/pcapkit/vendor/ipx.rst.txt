============================================================
:class:`~pcapkit.protocols.internet.ipx.IPX` Vendor Crawlers
============================================================

.. module:: pcapkit.vendor.ipx

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.ipx.IPX` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`IPX_Packet <pcapkit.vendor.ipx.packet.Packet>`
     - IPX Packet Types [*]_
   * - :class:`IPX_Socket <pcapkit.vendor.ipx.socket.Socket>`
     - IPX Socket Types [*]_

IPX Packet Types
================

.. module:: pcapkit.vendor.ipx.packet

This module contains the vendor crawler for **IPX Packet Types**,
which is automatically generating :class:`pcapkit.const.ipx.packet.Packet`.

.. autoclass:: pcapkit.vendor.ipx.packet.Packet
   :members: FLAG, LINK
   :show-inheritance:

Socket Types
============

.. module:: pcapkit.vendor.ipx.socket

This module contains the vendor crawler for **Socket Types**,
which is automatically generating :class:`pcapkit.const.ipx.socket.Socket`.

.. autoclass:: pcapkit.vendor.ipx.socket.Socket
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#IPX_packet_structure
.. [*] https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#Socket_number
