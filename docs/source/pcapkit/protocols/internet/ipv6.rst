IPv6 - Internet Protocol version 6
==================================

.. module:: pcapkit.protocols.internet.ipv6

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

.. autoclass:: pcapkit.protocols.internet.ipv6.IPv6
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: src
   .. autoproperty:: dst
   .. autoproperty:: extension_headers

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: _decode_next_layer

   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.ipv6

.. autoclass:: pcapkit.protocols.schema.internet.ipv6.IPv6
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.schema.internet.ipv6.IPv6Hextet
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.ipv6

.. autoclass:: pcapkit.protocols.data.internet.ipv6.IPv6
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. attribute:: class
      :type: int

      Traffic class.

      .. note::

         This field is conflict with :keyword:`class` keyword. To access this field,
         directly use :func:`getattr` instead.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv6_packet
