UDP - User Datagram Protocol
============================

.. module:: pcapkit.protocols.transport.udp

:mod:`pcapkit.protocols.transport.udp` contains
:class:`~pcapkit.protocols.transport.udp.UDP` only,
which implements extractor for User Datagram Protocol
(UDP) [*]_, whose structure is described as below:

======= ========= ===================== ===============================
Octets      Bits        Name                    Description
======= ========= ===================== ===============================
  0           0   ``udp.srcport``             Source Port
  2          16   ``udp.dstport``             Destination Port
  4          32   ``udp.len``                 Length (header includes)
  6          48   ``udp.checksum``            Checksum
======= ========= ===================== ===============================

.. autoclass:: pcapkit.protocols.transport.udp.UDP
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. autoattribute:: __proto__
      :no-value:

   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.transport.udp

.. autoclass:: pcapkit.protocols.schema.transport.udp.UDP
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Data Models
-----------

.. module:: pcapkit.protocols.data.transport.udp

.. autoclass:: pcapkit.protocols.data.transport.udp.UDP
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/User_Datagram_Protocol
