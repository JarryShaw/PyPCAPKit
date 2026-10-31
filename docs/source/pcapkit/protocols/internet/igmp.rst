IGMP - Internet Group Management Protocol
==========================================

.. module:: pcapkit.protocols.internet.igmp

:mod:`pcapkit.protocols.internet.igmp` contains
:class:`~pcapkit.protocols.internet.igmp.IGMP`, the abstract base of the
Internet Group Management Protocol (IGMP) [*]_ versions 1 and 2. Both share
the 8-octet structure below. :class:`IGMPv1 <pcapkit.protocols.internet.igmpv1.IGMP>`
and :class:`IGMPv2 <pcapkit.protocols.internet.igmpv2.IGMP>` set :attr:`version`,
and :attr:`alias` names the version of each message.

======= ========= ========================= ===================================
Octets      Bits        Name                    Description
======= ========= ========================= ===================================
  0           0   ``igmp.type``             Type
  1           8   ``igmp.max_resp_time``    Max Response Time
  2          16   ``igmp.checksum``         Checksum
  4          32   ``igmp.group``            Group Address
======= ========= ========================= ===================================

.. autoclass:: pcapkit.protocols.internet.igmp.IGMP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: version
   .. autoproperty:: alias
   .. autoproperty:: length

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __index__

   .. automethod:: _classify
   .. automethod:: _make_data

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.igmp

.. autoclass:: pcapkit.protocols.schema.internet.igmp.IGMP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.igmp

.. autoclass:: pcapkit.protocols.data.internet.igmp.IGMP
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
