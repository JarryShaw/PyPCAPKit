IPv6-Frag - Fragment Header for IPv6
====================================

.. module:: pcapkit.protocols.internet.ipv6_frag
.. module:: pcapkit.protocols.internet.ipv6_frag.protocol

:mod:`pcapkit.protocols.internet.ipv6_frag.protocol` contains
:class:`~pcapkit.protocols.internet.ipv6_frag.protocol.IPv6_Frag`
only, which implements the extractor for Fragment Header for
IPv6 (IPv6-Frag) [*]_, whose structure is described as
below:

======= ========= ========================= =======================
Octets      Bits        Name                    Description
======= ========= ========================= =======================
  0           0   ``frag.next``               Next Header
  1           8   ``frag.reserved_octet``     Reserved
  2          16   ``frag.offset``             Fragment Offset
  3          29   ``frag.reserved``           Reserved
  3          31   ``frag.mf``                 More Flag
  4          32   ``frag.id``                 Identification
======= ========= ========================= =======================

.. autoclass:: pcapkit.protocols.internet.ipv6_frag.protocol.IPv6_Frag
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __post_init__
   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.ipv6_frag.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.ipv6_frag``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ipv6_frag.schema.IPv6_Frag
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.internet.ipv6_frag.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.internet.ipv6_frag``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ipv6_frag.data.IPv6_Frag
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Fragment
