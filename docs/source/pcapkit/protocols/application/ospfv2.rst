OSPFv2 - Open Shortest Path First Version 2
===========================================

.. module:: pcapkit.protocols.application.ospfv2
.. module:: pcapkit.protocols.application.ospfv2.protocol

:mod:`pcapkit.protocols.application.ospfv2.protocol` contains
:class:`~pcapkit.protocols.application.ospfv2.protocol.OSPFv2`, which implements an
extractor for Open Shortest Path First version 2 (OSPFv2) [:rfc:`2328`], whose
header (:rfc:`2328#appendix-A.3.1`) is:

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

.. versionadded:: 1.8.1

   Takes over the parsing that :class:`~pcapkit.protocols.application.ospf.protocol.OSPF`
   carried, with its header schema and data model (:issue:`3105`).

.. autoclass:: pcapkit.protocols.application.ospfv2.protocol.OSPFv2
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
   .. automethod:: _read_encrypt_auth
   .. automethod:: _make_encrypt_auth
   .. automethod:: _make_id_numbers

Header Schemas
--------------

.. module:: pcapkit.protocols.application.ospfv2.schema

.. autoclass:: pcapkit.protocols.application.ospfv2.schema.OSPFv2
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ospfv2.schema.CryptographicAuthentication
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.application.ospfv2.schema.ospf_auth_data_selector

Data Models
-----------

.. module:: pcapkit.protocols.application.ospfv2.data

.. autoclass:: pcapkit.protocols.application.ospfv2.data.OSPFv2
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ospfv2.data.CryptographicAuthentication
   :members:
   :show-inheritance:
