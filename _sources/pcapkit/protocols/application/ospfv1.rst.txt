OSPFv1 - Open Shortest Path First Version 1
===========================================

.. module:: pcapkit.protocols.application.ospfv1
.. module:: pcapkit.protocols.application.ospfv1.protocol

:mod:`pcapkit.protocols.application.ospfv1.protocol` contains
:class:`~pcapkit.protocols.application.ospfv1.protocol.OSPFv1`, which implements an
extractor for Open Shortest Path First version 1 (OSPFv1) [:rfc:`1131`], obsoleted
by :rfc:`1247`. Its header (:rfc:`1131` Section A.2) is laid out as OSPFv2's:

.. table::

   ====== ===== ================== ===============================
   Octets Bits  Name               Description
   ====== ===== ================== ===============================
   0          0 ``ospf.version``   Version Number
   ------ ----- ------------------ -------------------------------
   1          8 ``ospf.type``      Type
   ------ ----- ------------------ -------------------------------
   2         16 ``ospf.len``       Packet Length (header included)
   ------ ----- ------------------ -------------------------------
   4         32 ``ospf.router_id`` Router ID
   ------ ----- ------------------ -------------------------------
   8         64 ``ospf.area_id``   Area ID
   ------ ----- ------------------ -------------------------------
   12        96 ``ospf.chksum``    Checksum
   ------ ----- ------------------ -------------------------------
   14       112 ``ospf.autype``    Authentication Type
   ------ ----- ------------------ -------------------------------
   16       128 ``ospf.auth``      Authentication
   ====== ===== ================== ===============================

It defines packet types 1 to 5 alone (Section A.2) and AuType 0 and 1 alone
(Appendix E), which :class:`~pcapkit.const.ospfv1.packet.Packet` and
:class:`~pcapkit.const.ospfv1.authentication.Authentication` name, rather than OSPFv2's
IANA registries. Its Authentication field is kept as captured: the cryptographic
authentication of :rfc:`2328#appendix-D.3` is OSPFv2's.

.. versionadded:: 1.8.1

.. autoclass:: pcapkit.protocols.application.ospfv1.protocol.OSPFv1
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

.. module:: pcapkit.protocols.application.ospfv1.schema

.. autoclass:: pcapkit.protocols.application.ospfv1.schema.OSPFv1
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.application.ospfv1.data

.. autoclass:: pcapkit.protocols.application.ospfv1.data.OSPFv1
   :members:
   :show-inheritance:
