MSTP - Multiple Spanning Tree Protocol
============================================

.. module:: pcapkit.protocols.application.mstp
.. module:: pcapkit.protocols.application.mstp.protocol

:mod:`pcapkit.protocols.application.mstp.protocol` holds
:class:`~pcapkit.protocols.application.mstp.protocol.MSTP`, the extractor for the
MST BPDU of the Multiple Spanning Tree Protocol (MSTP) [IEEE 802.1Q-2022 clause 14],
an RST BPDU of the Common and Internal Spanning Tree (CIST) extended by the MST
Configuration Identifier, the CIST's regional fields and an MSTI Configuration
Message for each Multiple Spanning Tree Instance (MSTI):

.. table::

   ====== ===== ==================================== ===================================
   Octets Bits  Name                                 Description
   ====== ===== ==================================== ===================================
   0          0                                      Protocol Identifier, zero, not kept
   ------ ----- ------------------------------------ -----------------------------------
   2         16 ``stp.protocol_version``             Protocol Version Identifier
   ------ ----- ------------------------------------ -----------------------------------
   3         24 ``stp.type``                         BPDU Type
   ------ ----- ------------------------------------ -----------------------------------
   4         32 ``stp.flags``                        CIST Flags
   ------ ----- ------------------------------------ -----------------------------------
   5         40 ``stp.cist_root_id``                 CIST Root Identifier
   ------ ----- ------------------------------------ -----------------------------------
   13       104 ``stp.cist_external_root_path_cost`` CIST External Root Path Cost
   ------ ----- ------------------------------------ -----------------------------------
   17       136 ``stp.cist_regional_root_id``        CIST Regional Root Identifier
   ------ ----- ------------------------------------ -----------------------------------
   25       200 ``stp.cist_port_id``                 CIST Port Identifier
   ------ ----- ------------------------------------ -----------------------------------
   27       216 ``stp.message_age``                  Message Age
   ------ ----- ------------------------------------ -----------------------------------
   29       232 ``stp.max_age``                      Max Age
   ------ ----- ------------------------------------ -----------------------------------
   31       248 ``stp.hello_time``                   Hello Time
   ------ ----- ------------------------------------ -----------------------------------
   33       264 ``stp.forward_delay``                Forward Delay
   ------ ----- ------------------------------------ -----------------------------------
   35       280 ``stp.version_1_length``             Version 1 Length, zero
   ------ ----- ------------------------------------ -----------------------------------
   36       288 ``stp.version_3_length``             Version 3 Length
   ------ ----- ------------------------------------ -----------------------------------
   38       304 ``stp.config_id``                    MST Configuration Identifier
   ------ ----- ------------------------------------ -----------------------------------
   89       712 ``stp.cist_internal_root_path_cost`` CIST Internal Root Path Cost
   ------ ----- ------------------------------------ -----------------------------------
   93       744 ``stp.cist_bridge_id``               CIST Bridge Identifier
   ------ ----- ------------------------------------ -----------------------------------
   101      808 ``stp.cist_remaining_hops``          CIST Remaining Hops
   ------ ----- ------------------------------------ -----------------------------------
   102      816 ``stp.msti``                         MSTI Configuration Messages
   ====== ===== ==================================== ===================================

IEEE 802.1Q-2022 clause 14.4 decodes a BPDU of BPDU Type ``0x02`` and version 3 or
more as an MST BPDU where it holds 102 octets or more, a Version 1 Length of zero
and a Version 3 Length counting 0 to 64 MSTI Configuration Messages after the 64
octets every MST BPDU has there; anything else of that type is an RST BPDU. Only
version 3 is read and built here: a later version holding all that is the SPT BPDU
of Shortest Path Bridging, version 4, which extends the MST BPDU past its messages
and which :mod:`pcapkit` does not dissect. Octets past the messages of an MST BPDU
are kept undissected.

.. versionadded:: 1.9.0

.. autoclass:: pcapkit.protocols.application.mstp.protocol.MSTP
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
   .. automethod:: _read_msti
   .. automethod:: _make_msti

Header Schemas
--------------

.. module:: pcapkit.protocols.application.mstp.schema

.. autoclass:: pcapkit.protocols.application.mstp.schema.MSTP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.mstp.schema.MSTIMessage
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.application.mstp.schema.mstp_msti_length

Data Models
-----------

.. module:: pcapkit.protocols.application.mstp.data

.. autoclass:: pcapkit.protocols.application.mstp.data.MSTP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.mstp.data.ConfigID
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.mstp.data.MSTIFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.mstp.data.MSTIMessage
   :members:
   :show-inheritance:
