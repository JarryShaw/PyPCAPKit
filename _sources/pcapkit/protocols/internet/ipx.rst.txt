IPX - Internetwork Packet Exchange
==================================

:mod:`pcapkit.protocols.internet.ipx` contains
:class:`~pcapkit.protocols.internet.ipx.IPX` only,
which implements extractor for Internetwork Packet
Exchange (IPX) [*]_, whose structure is described
as below:

======= ========= ====================== =====================================
Octets      Bits        Name                    Description
======= ========= ====================== =====================================
  0           0   ``ipx.cksum``             Checksum
  2          16   ``ipx.len``               Packet Length (header includes)
  4          32   ``ipx.count``             Transport Control (hop count)
  5          40   ``ipx.type``              Packet Type
  6          48   ``ipx.dst``               Destination Address
  18        144   ``ipx.src``               Source Address
======= ========= ====================== =====================================

.. raw:: html

   <br />

.. automodule:: pcapkit.protocols.internet.ipx
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_IPX

   :bases: TypedDict

   Structure of IPX header [:rfc:`1132`].

   .. attribute:: chksum
      :type: bytes

      Checksum.

   .. attribute:: len
      :type: int

      Packet length (header includes).

   .. attribute:: count
      :type: int

      Transport control (hop count).

   .. attribute:: type
      :type: pcapkit.const.ipx.packet.Packet

      Packet type.

   .. attribute:: dst
      :type: DataType_IPX_Address

      Destination address.

   .. attribute:: src
      :type: DataType_IPX_Address

      Source address.

For IPX address field, its structure is described as below:

======= ========= ======================= ========================
Octets      Bits        Name                    Description
======= ========= ======================= ========================
  0           0   ``ipx.addr.network``        Network Number
  4          32   ``ipx.addr.node``           Node Number
  10         80   ``ipx.addr.socket``         Socket Number
======= ========= ======================= ========================

.. raw:: html

   <br />

.. class:: DataType_IPX_Address

   :bases: TypedDict

   Structure of IPX address.

   .. attribute:: network
      :type: str

      Network number (``:`` separated).

   .. attribute:: node
      :type: str

      Node number (``-`` separated).

   .. attribute:: socket
      :type: pcapkit.const.ipx.socket.Socket

      Socket number.

   .. attribute:: addr
      :type: str

      Full address (``:`` separated).

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange
