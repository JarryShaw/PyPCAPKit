UDP - User Datagram Protocol
============================

.. module:: pcapkit.protocols.transport.udp
.. module:: pcapkit.protocols.transport.udp.protocol

:mod:`pcapkit.protocols.transport.udp.protocol` contains
:class:`~pcapkit.protocols.transport.udp.protocol.UDP` only,
which implements the extractor for User Datagram Protocol
(UDP) [*]_, whose structure is:

======= ========= ===================== ===============================
Octets      Bits        Name                    Description
======= ========= ===================== ===============================
  0           0   ``udp.srcport``             Source Port
  2          16   ``udp.dstport``             Destination Port
  4          32   ``udp.len``                 Length (header included)
  6          48   ``udp.checksum``            Checksum
======= ========= ===================== ===============================

.. autoclass:: pcapkit.protocols.transport.udp.protocol.UDP
   :no-members:
   :show-inheritance:

   .. autoattribute:: __proto__
      :no-value:

   .. autoattribute:: __proto_key__
      :no-value:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _verify_pseudo_checksum

Header Schemas
--------------

.. module:: pcapkit.protocols.transport.udp.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.transport.udp``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.transport.udp.schema.UDP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.transport.udp.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.transport.udp``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.transport.udp.data.UDP
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/User_Datagram_Protocol
