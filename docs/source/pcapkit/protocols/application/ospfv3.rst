OSPFv3 - Open Shortest Path First Version 3
===========================================

.. module:: pcapkit.protocols.application.ospfv3
.. module:: pcapkit.protocols.application.ospfv3.protocol

:mod:`pcapkit.protocols.application.ospfv3.protocol` contains
:class:`~pcapkit.protocols.application.ospfv3.protocol.OSPFv3`, which implements an
extractor for OSPF for IPv6 (OSPFv3) [:rfc:`5340`], whose 16-octet header
(:rfc:`5340#appendix-A.3.1`) has an Instance ID and a reserved octet in place of
OSPFv2's AuType and Authentication:

.. table::

   ====== ===== ==================== ===============================
   Octets Bits  Name                 Description
   ====== ===== ==================== ===============================
   0          0 ``ospf.version``     Version Number
   ------ ----- -------------------- -------------------------------
   1          8 ``ospf.type``        Type
   ------ ----- -------------------- -------------------------------
   2         16 ``ospf.len``         Packet Length (header included)
   ------ ----- -------------------- -------------------------------
   4         32 ``ospf.router_id``   Router ID
   ------ ----- -------------------- -------------------------------
   8         64 ``ospf.area_id``     Area ID
   ------ ----- -------------------- -------------------------------
   12        96 ``ospf.chksum``      Checksum
   ------ ----- -------------------- -------------------------------
   14       112 ``ospf.instance_id`` Instance ID
   ------ ----- -------------------- -------------------------------
   15       120 ``ospf.reserved``    Reserved
   ====== ===== ==================== ===============================

.. versionadded:: 1.8.1

.. autoclass:: pcapkit.protocols.application.ospfv3.protocol.OSPFv3
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: length

   .. rubric:: Methods

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make

   .. rubric:: Data Models

   .. automethod:: __length_hint__

   .. rubric:: Utilities

   .. automethod:: _make_data

Header Schemas
--------------

.. module:: pcapkit.protocols.application.ospfv3.schema

.. autoclass:: pcapkit.protocols.application.ospfv3.schema.OSPFv3
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.application.ospfv3.data

.. autoclass:: pcapkit.protocols.application.ospfv3.data.OSPFv3
   :members:
   :show-inheritance:
