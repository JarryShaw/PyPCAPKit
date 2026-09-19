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

.. note::

   This crawler no longer crawls. The table it used to scrape was deleted from
   the Wikipedia article on 2026-08-25, and the registry itself is closed, so
   the data is now maintained by hand in the ``DATA`` and ``RANGES`` mappings of
   :mod:`pcapkit.vendor.ipx.socket`, and the class defines no ``LINK``. The
   footnote below points at the last revision that still carried the table --
   what the hand-maintained registry was transcribed from, not a page the
   crawler fetches. See #507.

.. autoclass:: pcapkit.vendor.ipx.socket.Socket
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#IPX_packet_structure
.. [*] https://en.wikipedia.org/w/index.php?title=Internetwork_Packet_Exchange&oldid=1368657333
