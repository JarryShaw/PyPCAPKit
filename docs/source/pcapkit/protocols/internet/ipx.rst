IPX - Internetwork Packet Exchange
==================================

.. module:: pcapkit.protocols.internet.ipx
.. module:: pcapkit.protocols.internet.ipx.protocol

:mod:`pcapkit.protocols.internet.ipx.protocol` contains
:class:`~pcapkit.protocols.internet.ipx.protocol.IPX` only,
which implements the extractor for Internetwork Packet
Exchange (IPX) [*]_, whose structure is described
as below:

======= ========= ====================== =====================================
Octets      Bits        Name                    Description
======= ========= ====================== =====================================
  0           0   ``ipx.chksum``            Checksum
  2          16   ``ipx.len``               Packet Length (header included)
  4          32   ``ipx.count``             Transport Control (hop count)
  5          40   ``ipx.type``              Packet Type
  6          48   ``ipx.dst``               Destination Address
  18        144   ``ipx.src``               Source Address
======= ========= ====================== =====================================

.. autoclass:: pcapkit.protocols.internet.ipx.protocol.IPX
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register

   .. automethod:: _make_data
   .. automethod:: _next_exthdr_depth

   .. automethod:: __index__

   .. autoattribute:: __proto__
      :no-value:
   .. autoattribute:: __proto_key__
      :no-value:

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.ipx.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.ipx``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ipx.schema.IPX
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.internet.ipx.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.internet.ipx``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ipx.data.IPX
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipx.data.Address
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange
