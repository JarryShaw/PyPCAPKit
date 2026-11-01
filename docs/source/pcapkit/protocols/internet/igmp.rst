IGMP - Internet Group Management Protocol
==========================================

.. module:: pcapkit.protocols.internet.igmp

:mod:`pcapkit.protocols.internet.igmp` contains
:class:`~pcapkit.protocols.internet.igmp.IGMP`, the abstract base of the
Internet Group Management Protocol (IGMP) [*]_ versions 1, 2 and 3. IGMPv1
and IGMPv2 share the 8-octet structure below.
:class:`IGMPv1 <pcapkit.protocols.internet.igmpv1.IGMPv1>` and
:class:`IGMPv2 <pcapkit.protocols.internet.igmpv2.IGMPv2>` set
:attr:`~pcapkit.protocols.internet.igmp.IGMP.version` and reuse this schema and
data model as-is; IGMPv3's wire format differs materially by message, so
:class:`IGMPv3 <pcapkit.protocols.internet.igmpv3.IGMPv3>` carries its own
instead -- see :doc:`igmpv3`.
:attr:`~pcapkit.protocols.internet.igmp.IGMP.alias` names the protocol each
message is read as: ``'IGMP'`` for IGMPv1, the name :rfc:`1112` gives it, and
``'IGMPv2'`` or ``'IGMPv3'`` for the others.

The structure is keyed as for IGMPv1; an IGMPv2 message's keys start ``igmpv2``
instead:

======= ========= ========================= ===================================
Octets      Bits        Name                    Description
======= ========= ========================= ===================================
  0           0   ``igmpv1.type``           Type
  1           8   ``igmpv1.max_resp_time``  Max Response Time
  2          16   ``igmpv1.checksum``       Checksum
  4          32   ``igmpv1.group``          Group Address
======= ========= ========================= ===================================

.. autoclass:: pcapkit.protocols.internet.igmp.IGMP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: version
   .. autoproperty:: alias
   .. autoproperty:: length

   .. automethod:: id

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
