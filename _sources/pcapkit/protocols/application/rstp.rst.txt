RSTP - Rapid Spanning Tree Protocol
=========================================

.. module:: pcapkit.protocols.application.rstp
.. module:: pcapkit.protocols.application.rstp.protocol

:mod:`pcapkit.protocols.application.rstp.protocol` holds
:class:`~pcapkit.protocols.application.rstp.protocol.RSTP`, the extractor for the
RST BPDU of the Rapid Spanning Tree Protocol (RSTP) [:ieee:`802.1Q-2022` clause 14],
laid out as the Configuration BPDU with a Version 1 Length after it:

.. table::

   ====== ===== ========================= ===================================
   Octets Bits  Name                      Description
   ====== ===== ========================= ===================================
   0          0                           Protocol Identifier, zero, not kept
   ------ ----- ------------------------- -----------------------------------
   2         16 ``stp.protocol_version``  Protocol Version Identifier
   ------ ----- ------------------------- -----------------------------------
   3         24 ``stp.type``              BPDU Type
   ------ ----- ------------------------- -----------------------------------
   4         32 ``stp.flags``             Flags
   ------ ----- ------------------------- -----------------------------------
   5         40 ``stp.root_id``           Root Identifier
   ------ ----- ------------------------- -----------------------------------
   13       104 ``stp.root_path_cost``    Root Path Cost
   ------ ----- ------------------------- -----------------------------------
   17       136 ``stp.bridge_id``         Bridge Identifier
   ------ ----- ------------------------- -----------------------------------
   25       200 ``stp.port_id``           Port Identifier
   ------ ----- ------------------------- -----------------------------------
   27       216 ``stp.message_age``       Message Age
   ------ ----- ------------------------- -----------------------------------
   29       232 ``stp.max_age``           Max Age
   ------ ----- ------------------------- -----------------------------------
   31       248 ``stp.hello_time``        Hello Time
   ------ ----- ------------------------- -----------------------------------
   33       264 ``stp.forward_delay``     Forward Delay
   ------ ----- ------------------------- -----------------------------------
   35       280 ``stp.version_1_length``  Version 1 Length, zero
   ====== ===== ========================= ===================================

:ieee:`802.1Q-2022` clause 14.4 decodes a BPDU of BPDU Type ``0x02`` and version 2 as
an RST BPDU, and one of version 3 or more too, where it does not hold what an MST
BPDU does; such a BPDU of 35 octets ends before its Version 1 Length. Its
flags carry the Port Role and the Proposal, Learning, Forwarding and Agreement
flags beside the Topology Change ones.

.. versionadded:: 1.9.0

.. autoclass:: pcapkit.protocols.application.rstp.protocol.RSTP
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

Header Schemas
--------------

.. module:: pcapkit.protocols.application.rstp.schema

.. autoclass:: pcapkit.protocols.application.rstp.schema.RSTP
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.application.rstp.schema.rstp_version_1_length

Data Models
-----------

.. module:: pcapkit.protocols.application.rstp.data

.. autoclass:: pcapkit.protocols.application.rstp.data.RSTP
   :members:
   :show-inheritance:
