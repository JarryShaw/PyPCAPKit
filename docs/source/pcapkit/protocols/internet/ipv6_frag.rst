IPv6-Frag - Fragment Header for IPv6
====================================

.. module:: pcapkit.protocols.internet.ipv6_frag

:mod:`pcapkit.protocols.internet.ipv6_frag` contains
:class:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag`
only, which implements extractor for Fragment Header for
IPv6 (IPv6-Frag) [*]_, whose structure is described as
below:

======= ========= ==================== =======================
Octets      Bits        Name                    Description
======= ========= ==================== =======================
  0           0   ``frag.next``               Next Header
  1           8                               Reserved
  2          16   ``frag.offset``             Fragment Offset
  3          29                               Reserved
  3          31   ``frag.mf``                 More Flag
  4          32   ``frag.id``                 Identification
======= ========= ==================== =======================

.. autoclass:: pcapkit.protocols.internet.ipv6_frag.IPv6_Frag
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __post_init__
   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.ipv6_frag

.. autoclass:: pcapkit.protocols.schema.internet.ipv6_frag.IPv6_Frag
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.ipv6_frag

.. autoclass:: pcapkit.protocols.data.internet.ipv6_frag.IPv6_Frag
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Fragment
