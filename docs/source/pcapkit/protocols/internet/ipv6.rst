IPv6 - Internet Protocol Version 6
==================================

.. module:: pcapkit.protocols.internet.ipv6
.. module:: pcapkit.protocols.internet.ipv6.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.internet.ipv6.IPV6_HEADER_LEN`` and
   ``pcapkit.protocols.internet.ipv6.IPV6_NEXT_HEADER_OFFSET``, with no alias: they are
   in this module, and :mod:`pcapkit.protocols.internet.ipv6` exports the protocol class
   alone (:issue:`2534`).

:mod:`pcapkit.protocols.internet.ipv6.protocol` contains
:class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6` only,
which implements the extractor for Internet Protocol
version 6 (IPv6) [*]_, whose structure is described
as below:

======= ========= ===================== =======================================
Octets      Bits        Name                    Description
======= ========= ===================== =======================================
  0           0   ``ipv6.version``            Version (``6``)
  0           4   ``ipv6.class``              Traffic Class
  1          12   ``ipv6.label``              Flow Label
  4          32   ``ipv6.payload``            Payload Length (header excluded)
  6          48   ``ipv6.next``               Next Header
  7          56   ``ipv6.limit``              Hop Limit
  8          64   ``ipv6.src``                Source Address
  24        192   ``ipv6.dst``                Destination Address
======= ========= ===================== =======================================

.. autoclass:: pcapkit.protocols.internet.ipv6.protocol.IPv6
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: src
   .. autoproperty:: dst
   .. autoproperty:: extension_headers

   .. automethod:: read
   .. automethod:: make
   .. automethod:: unpack
   .. automethod:: id

   .. automethod:: __index__
   .. automethod:: __post_init__

   .. automethod:: _make_data
   .. automethod:: _decode_next_layer
   .. automethod:: _read_ip_hextet
   .. automethod:: _import_next_layer

Protocol Constants
------------------

.. autodata:: pcapkit.protocols.internet.ipv6.protocol.IPV6_HEADER_LEN

.. autodata:: pcapkit.protocols.internet.ipv6.protocol.IPV6_NEXT_HEADER_OFFSET

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.ipv6.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.ipv6``, with no alias: the module moved here
   (:issue:`2534`).

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.ipv6.jumbo_payload_length``, now
   :func:`pcapkit.corekit.schema.jumbogram.jumbo_payload_length` (:issue:`2674`).

.. autodata:: pcapkit.protocols.internet.ipv6.schema.IP_MAX_LENGTH

.. autoclass:: pcapkit.protocols.internet.ipv6.schema.IPv6
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.internet.ipv6.schema.IPv6Hextet
   :members:
   :show-inheritance:

   .. attribute:: version
      :type: int

      Version.

   .. attribute:: class
      :type: int

      Traffic class.

   .. attribute:: label
      :type: int

      Flow label.

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.internet.ipv6.schema.jumbogram_error

Data Models
-----------

.. module:: pcapkit.protocols.internet.ipv6.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.internet.ipv6``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ipv6.data.IPv6
   :members:
   :show-inheritance:

   .. attribute:: class
      :type: int

      Traffic class.

      .. note::

         This field's name conflicts with the :keyword:`class` keyword, so
         access it with :func:`getattr` instead.

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IPv6_packet
