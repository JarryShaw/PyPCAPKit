STPv0 - Spanning Tree Protocol
====================================

.. module:: pcapkit.protocols.application.stpv0
.. module:: pcapkit.protocols.application.stpv0.protocol

:mod:`pcapkit.protocols.application.stpv0.protocol` holds
:class:`~pcapkit.protocols.application.stpv0.protocol.STPv0`, the extractor for the
Configuration and Topology Change Notification (TCN) BPDUs of the Spanning Tree
Protocol (STP) [IEEE 802.1D-2004 clause 9], laid out as below. A TCN BPDU ends
after its BPDU Type.

.. table::

   ====== ===== ======================== ===========================
   Octets Bits  Name                     Description
   ====== ===== ======================== ===========================
   0          0                          Protocol Identifier, zero, not kept
   ------ ----- ------------------------ ---------------------------
   2         16 ``stp.protocol_version`` Protocol Version Identifier
   ------ ----- ------------------------ ---------------------------
   3         24 ``stp.type``             BPDU Type
   ------ ----- ------------------------ ---------------------------
   4         32 ``stp.flags``            Flags
   ------ ----- ------------------------ ---------------------------
   5         40 ``stp.root_id``          Root Identifier
   ------ ----- ------------------------ ---------------------------
   13       104 ``stp.root_path_cost``   Root Path Cost
   ------ ----- ------------------------ ---------------------------
   17       136 ``stp.bridge_id``        Bridge Identifier
   ------ ----- ------------------------ ---------------------------
   25       200 ``stp.port_id``          Port Identifier
   ------ ----- ------------------------ ---------------------------
   27       216 ``stp.message_age``      Message Age
   ------ ----- ------------------------ ---------------------------
   29       232 ``stp.max_age``          Max Age
   ------ ----- ------------------------ ---------------------------
   31       248 ``stp.hello_time``       Hello Time
   ------ ----- ------------------------ ---------------------------
   33       264 ``stp.forward_delay``    Forward Delay
   ====== ===== ======================== ===========================

IEEE 802.1Q-2022 clause 14.4 decodes either BPDU by its type, whatever its Protocol
Version Identifier, so the version is kept as captured and checked against none.

.. versionadded:: 1.9.0

.. autoclass:: pcapkit.protocols.application.stpv0.protocol.STPv0
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: name
   .. autoproperty:: version
   .. autoproperty:: length

   .. rubric:: Methods

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make

   .. rubric:: Data Models

   .. automethod:: __length_hint__

   .. rubric:: Utilities

   .. automethod:: _make_data
   .. automethod:: _read_config_flags
   .. automethod:: _make_config_flags

Header Schemas
--------------

.. module:: pcapkit.protocols.application.stpv0.schema

.. autoclass:: pcapkit.protocols.application.stpv0.schema.STPv0
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.application.stpv0.schema.stp_config_body

Data Models
-----------

.. module:: pcapkit.protocols.application.stpv0.data

.. autoclass:: pcapkit.protocols.application.stpv0.data.STPv0
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.stpv0.data.ConfigFlags
   :members:
   :show-inheritance:
