UDP - User Datagram Protocol
============================

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

.. automodule:: pcapkit.protocols.transport.udp
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_UDP

   :bases: TypedDict

   Structure of UDP header [:rfc:`768`].

   .. attribute:: srcport
      :type: int

      Source port.

   .. attribute:: dstport
      :type: int

      Destination port.

   .. attribute:: len
      :type: int

      Length.

   .. attribute:: checksum
      :type: bytes

      Checksum.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/User_Datagram_Protocol
