IPv6 - Internet Protocol version 6
==================================

.. module:: pcapkit.protocols.internet.ipv6
.. module:: pcapkit.protocols.data.internet.ipv6

:mod:`pcapkit.protocols.internet.ipv6` contains
:class:`~pcapkit.protocols.internet.ipv6.IPv6` only,
which implements extractor for Internet Protocol
version 6 (IPv6) [*]_, whose structure is described
as below:

======= ========= ===================== =======================================
Octets      Bits        Name                    Description
======= ========= ===================== =======================================
  0           0   ``ip.version``              Version (``6``)
  0           4   ``ip.class``                Traffic Class
  1          12   ``ip.label``                Flow Label
  4          32   ``ip.payload``              Payload Length (header excludes)
  6          48   ``ip.next``                 Next Header
  7          56   ``ip.limit``                Hop Limit
  8          64   ``ip.src``                  Source Address
  24        192   ``ip.dst``                  Destination Address
======= ========= ===================== =======================================

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.internet.ipv6.IPv6
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
   .. autoproperty:: extension_headers

   .. automethod:: read
   .. automethod:: make
   .. automethod:: id

   .. automethod:: _read_ip_hextet
   .. automethod:: _read_ip_addr
   .. automethod:: _decode_next_layer

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.internet.ipv6.IPv6(version, class, label, payload, next, limit, src, dst)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: version

   .. attribute:: class
      :type: int

      Traffic class.

      .. note::

         This field is conflict with :keyword:`class` keyword. To access this field,
         directly use :func:`getattr` instead.

   .. autoattribute:: label
   .. autoattribute:: payload
   .. autoattribute:: next
   .. autoattribute:: limit
   .. autoattribute:: src
   .. autoattribute:: dst

   .. autoattribute:: fragment
   .. autoattribute:: protocol
   .. autoattribute:: hdr_len
   .. autoattribute:: raw_len

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv6_packet
