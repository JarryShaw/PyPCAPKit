UDP - User Datagram Protocol
============================

.. module:: pcapkit.protocols.transport.udp
.. module:: pcapkit.protocols.data.transport.udp

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

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.transport.udp.UDP
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: read
   .. automethod:: make

   .. autoattribute:: __proto__
      :no-value:

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.transport.udp.UDP(srcport, dstport, len, checksum)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: srcport
   .. autoattribute:: dstport
   .. autoattribute:: len
   .. autoattribute:: checksum

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/User_Datagram_Protocol
