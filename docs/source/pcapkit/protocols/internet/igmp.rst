IGMP - Internet Group Management Protocol
==========================================

.. module:: pcapkit.protocols.internet.igmp

:mod:`pcapkit.protocols.internet.igmp` contains
:class:`~pcapkit.protocols.internet.igmp.IGMP` only,
which implements the extractor for Internet Group
Management Protocol (IGMP) [*]_ versions 1, 2 and 3.

IGMPv1 and IGMPv2 share one 8-octet message shape:

======= ========= ============================= ===================================
Octets      Bits        Name                          Description
======= ========= ============================= ===================================
  0           0   ``igmp.type``                 Type
  1           8   ``igmp.body.max_resp_code``    Max Response Code
  2          16   ``igmp.body.checksum``         Checksum
  4          32   ``igmp.body.group``            Group Address
======= ========= ============================= ===================================

An IGMPv3 Membership Query (type ``0x11``, shared with v1/v2) reuses that
8-octet layout and, at least 12 octets long overall, appends a source-list
extension; an IGMPv3 Membership Report (type ``0x22``) has an unrelated
group-record-list shape of its own. See the module docstring below for both
layouts in full.

.. autoclass:: pcapkit.protocols.internet.igmp.IGMP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.igmp

.. autoclass:: pcapkit.protocols.schema.internet.igmp.IGMP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.igmp.GroupBody
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.igmp.QueryExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.igmp.ReportBody
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.igmp.GroupRecord
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.igmp

.. autoclass:: pcapkit.protocols.data.internet.igmp.IGMP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.igmp.GroupAddressMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.igmp.Version3MembershipReport
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.igmp.GroupRecord
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
