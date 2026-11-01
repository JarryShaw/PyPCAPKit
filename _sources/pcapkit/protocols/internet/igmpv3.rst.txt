IGMPv3 - Internet Group Management Protocol version 3
==============================================================

.. module:: pcapkit.protocols.internet.igmpv3

:mod:`pcapkit.protocols.internet.igmpv3` contains
:class:`~pcapkit.protocols.internet.igmpv3.IGMP`, which implements an
extractor for Internet Group Management Protocol version 3 (IGMPv3)
[:rfc:`3376`]. Unlike :class:`IGMPv1 <pcapkit.protocols.internet.igmpv1.IGMP>`
and :class:`IGMPv2 <pcapkit.protocols.internet.igmpv2.IGMP>`, which reuse the
abstract base's own 8-octet schema and data model (see
:mod:`~pcapkit.protocols.internet.igmp`), IGMPv3 defines two message shapes
of its own:

An IGMPv3 Membership Query (type ``0x11``, shared with v1/v2) reuses the
8-octet layout IGMPv1/v2 share and, when at least 12 octets long overall,
appends a source-list extension:

======= ========= ================================== ===================================
Octets      Bits        Name                               Description
======= ========= ================================== ===================================
  0           0   ``igmp.type``                       Type
  1           8   ``igmp.body.max_resp_code``          Max Response Code
  2          16   ``igmp.body.checksum``                Checksum
  4          32   ``igmp.body.group``                   Group Address
  8          64   ``igmp.body.ext.flags``               Resv / S Flag / QRV
  9          72   ``igmp.body.ext.qqic``                Querier's Query Interval Code
  10         80   ``igmp.body.ext.num_sources``         Number of Sources (N)
  12         96   ``igmp.body.ext.sources``             Source Address [1..N]
======= ========= ================================== ===================================

An IGMPv3 Membership Report (type ``0x22``) has an unrelated, materially
different shape of its own:

======= ========= ================================== ===================================
Octets      Bits        Name                               Description
======= ========= ================================== ===================================
  0           0   ``igmp.type``                       Type
  1           8   ``igmp.body.reserved_1``             Reserved
  2          16   ``igmp.body.checksum``                Checksum
  4          32   ``igmp.body.reserved_2``             Reserved
  6          48   ``igmp.body.num_group_records``      Number of Group Records (M)
  8          64   ``igmp.body.records``                Group Record [1..M]
======= ========= ================================== ===================================

.. autoclass:: pcapkit.protocols.internet.igmpv3.IGMP
   :no-members:
   :show-inheritance:

   .. autoproperty:: version
   .. autoproperty:: length

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_group_record
   .. automethod:: _make_data

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.igmpv3

.. autoclass:: pcapkit.protocols.schema.internet.igmpv3.IGMP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.igmpv3.Query
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.igmpv3.QueryExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.igmpv3.Report
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.igmpv3.GroupRecord
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.igmpv3

.. autoclass:: pcapkit.protocols.data.internet.igmpv3.IGMP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.igmpv3.Query
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.igmpv3.Report
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.igmpv3.GroupRecord
   :members:
   :show-inheritance:
