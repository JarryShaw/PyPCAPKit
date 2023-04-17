IPv6-Frag - Fragment Header for IPv6
====================================

.. module:: pcapkit.protocols.internet.ipv6_frag
.. module:: pcapkit.protocols.data.internet.ipv6_frag

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

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.internet.ipv6_frag.IPv6_Frag
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.internet.ipv6_frag.IPv6_Frag(next, offset, mf, id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: next
   .. autoattribute:: offset
   .. autoattribute:: mf
   .. autoattribute:: id

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Fragment
