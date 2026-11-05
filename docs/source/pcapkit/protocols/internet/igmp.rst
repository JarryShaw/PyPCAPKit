IGMP - Internet Group Management Protocol
==========================================

.. module:: pcapkit.protocols.internet.igmp
.. module:: pcapkit.protocols.internet.igmp.protocol

:mod:`pcapkit.protocols.internet.igmp.protocol` contains
:class:`~pcapkit.protocols.internet.igmp.protocol.IGMP`, the abstract base of the
Internet Group Management Protocol (IGMP) [*]_ versions 1, 2 and 3. IGMPv1
and IGMPv2 share the 8-octet structure below.
:class:`IGMPv1 <pcapkit.protocols.internet.igmpv1.protocol.IGMPv1>` and
:class:`IGMPv2 <pcapkit.protocols.internet.igmpv2.protocol.IGMPv2>` set
:attr:`~pcapkit.protocols.internet.igmp.protocol.IGMP.version` and reuse this schema and
data model as-is; IGMPv3's wire format differs materially by message, so
:class:`IGMPv3 <pcapkit.protocols.internet.igmpv3.protocol.IGMPv3>` carries its own
instead -- see :doc:`igmpv3`.
:attr:`~pcapkit.protocols.internet.igmp.protocol.IGMP.alias` names the protocol each
message is read as: ``'IGMP'`` for IGMPv1, the name :rfc:`1112` gives it, and
``'IGMPv2'`` or ``'IGMPv3'`` for the others. Constructing the base gives the
version class its ``version`` keyword names; without it, octets give the class
the message classifies as, and fields are refused. Its
:meth:`~pcapkit.protocols.internet.igmp.protocol.IGMP.from_data` gives the class the
``version`` of its data names: every IGMP data model carries one, ``1``, ``2`` or
``3``, set by the class that read or built the message and on no octet, so an
IGMPv1 and an IGMPv2 message read alike apart from it (:issue:`2574`).

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

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.protocols.internet.igmp.protocol.IGMP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: version
   .. autoproperty:: alias
   .. autoproperty:: length

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make
   .. automethod:: from_data

   .. automethod:: __index__
   .. automethod:: __init__
   .. automethod:: __new__

   .. automethod:: _make_data
   .. automethod:: _classify
   .. automethod:: _verify_checksum
   .. automethod:: _dispatch
   .. automethod:: _member_of_version

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.igmp.schema

.. autoclass:: pcapkit.protocols.internet.igmp.schema.IGMP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.internet.igmp.data

.. autoclass:: pcapkit.protocols.internet.igmp.data.IGMP
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
