IPX - Internetwork Packet Exchange
==================================

.. module:: pcapkit.protocols.internet.ipx
.. module:: pcapkit.protocols.data.internet.ipx

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

.. autoclass:: pcapkit.protocols.internet.ipx.IPX
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _read_ipx_address

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.internet.ipx.IPX(chksum, len, count, type, dst, src)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: chksum
   .. autoattribute:: len
   .. autoattribute:: count
   .. autoattribute:: type
   .. autoattribute:: dst
   .. autoattribute:: src

.. autoclass:: pcapkit.protocols.data.internet.ipx.Address(network, node, socket, addr)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: network
   .. autoattribute:: node
   .. autoattribute:: socket
   .. autoattribute:: addr

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange
