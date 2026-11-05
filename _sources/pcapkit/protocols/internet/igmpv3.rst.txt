IGMPv3 - Internet Group Management Protocol Version 3
==============================================================

.. module:: pcapkit.protocols.internet.igmpv3
.. module:: pcapkit.protocols.internet.igmpv3.protocol

:mod:`pcapkit.protocols.internet.igmpv3.protocol` contains
:class:`~pcapkit.protocols.internet.igmpv3.protocol.IGMPv3`, which implements an
extractor for Internet Group Management Protocol version 3 (IGMPv3)
[:rfc:`3376`]. Unlike :class:`IGMPv1 <pcapkit.protocols.internet.igmpv1.protocol.IGMPv1>`
and :class:`IGMPv2 <pcapkit.protocols.internet.igmpv2.protocol.IGMPv2>`, which reuse the
abstract base's own 8-octet schema and data model (see
:mod:`~pcapkit.protocols.internet.igmp.protocol`), IGMPv3 defines two message shapes
of its own:

An IGMPv3 Membership Query (type ``0x11``, shared with v1/v2) reuses the
8-octet layout IGMPv1/v2 share and, when at least 12 octets long overall,
appends a source-list extension:

======= ========= ================================== ===================================
Octets      Bits        Name                               Description
======= ========= ================================== ===================================
  0           0   ``igmpv3.type``                    Type
  1           8   ``igmpv3.max_resp_code``           Max Response Code
  2          16   ``igmpv3.checksum``                Checksum
  4          32   ``igmpv3.group``                   Group Address
  8          64   ``igmpv3.resv``                    Reserved (Resv)
  8          68   ``igmpv3.s_flag``                  Suppress Router-Side Processing (S)
  8          69   ``igmpv3.qrv``                     Querier's Robustness Variable (QRV)
  9          72   ``igmpv3.qqic``                    Querier's Query Interval Code
  10         80   ``igmpv3.num_sources``             Number of Sources (N)
  12         96   ``igmpv3.sources``                 Source Address [1..N]
======= ========= ================================== ===================================

An IGMPv3 Membership Report (type ``0x22``) has an unrelated, materially
different shape of its own:

======= ========= ================================== ===================================
Octets      Bits        Name                               Description
======= ========= ================================== ===================================
  0           0   ``igmpv3.type``                    Type
  1           8   ``igmpv3.reserved_1``              Reserved
  2          16   ``igmpv3.checksum``                Checksum
  4          32   ``igmpv3.reserved_2``              Reserved
  6          48   ``igmpv3.num_group_records``       Number of Group Records (M)
  8          64   ``igmpv3.records``                 Group Record [1..M]
======= ========= ================================== ===================================

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.protocols.internet.igmpv3.protocol.IGMPv3
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: version
   .. autoproperty:: length

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data
   .. automethod:: _make_group_record

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.igmpv3.schema

.. autoclass:: pcapkit.protocols.internet.igmpv3.schema.IGMPv3
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.igmpv3.schema.Query
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.igmpv3.schema.QueryExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.igmpv3.schema.Report
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.igmpv3.schema.GroupRecord
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.internet.igmpv3.data

.. autoclass:: pcapkit.protocols.internet.igmpv3.data.IGMPv3
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.igmpv3.data.Query
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.igmpv3.data.Report
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.igmpv3.data.GroupRecord
   :members:
   :show-inheritance:
