DCCP - Datagram Congestion Control Protocol
===========================================

.. module:: pcapkit.protocols.transport.dccp

:mod:`pcapkit.protocols.transport.dccp` contains
:class:`~pcapkit.protocols.transport.dccp.DCCP` only,
which implements the extractor for Datagram Congestion
Control Protocol (DCCP) [*]_, whose generic header is
described as below:

======= ========= ========================= =======================================
Octets      Bits        Name                    Description
======= ========= ========================= =======================================
  0           0   ``dccp.srcport``          Source Port
  2          16   ``dccp.dstport``          Destination Port
  4          32   ``dccp.hdr_len``          Data Offset
  5          40   ``dccp.ccval``            HC-Sender CCID Value (CCVal)
  5          44   ``dccp.cscov``            Checksum Coverage (CsCov)
  6          48   ``dccp.checksum``         Checksum
  8          64   ``dccp.reserved``         Reserved (Res)
  8          67   ``dccp.type``             Packet Type
  8          71   ``dccp.x``                Extended Sequence Numbers (X)
  9          72   ``dccp.seq_reserved``     Reserved (if X set)
  10         80   ``dccp.seq``              Sequence Number (48 bits if X set)
======= ========= ========================= =======================================

With ``X`` clear, the Sequence Number is 24 bits at octet 9 and the generic
header 12 octets long. The fields of the packet type, then the options, follow.

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.protocols.transport.dccp.DCCP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: register_option

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data
   .. automethod:: _verify_pseudo_checksum

   .. automethod:: _read_dccp_options
   .. automethod:: _read_opt_unassigned
   .. automethod:: _read_opt_padding
   .. automethod:: _read_opt_mandatory
   .. automethod:: _read_opt_slow_receiver
   .. automethod:: _read_opt_change
   .. automethod:: _read_opt_confirm
   .. automethod:: _read_opt_init_cookie
   .. automethod:: _read_opt_ndp_count
   .. automethod:: _read_opt_ack_vector
   .. automethod:: _read_opt_data_dropped
   .. automethod:: _read_opt_timestamp
   .. automethod:: _read_opt_timestamp_echo
   .. automethod:: _read_opt_elapsed_time
   .. automethod:: _read_opt_data_checksum

   .. automethod:: _make_dccp_options
   .. automethod:: _make_opt_unassigned
   .. automethod:: _make_opt_padding
   .. automethod:: _make_opt_mandatory
   .. automethod:: _make_opt_slow_receiver
   .. automethod:: _make_opt_change
   .. automethod:: _make_opt_confirm
   .. automethod:: _make_opt_init_cookie
   .. automethod:: _make_opt_ndp_count
   .. automethod:: _make_opt_ack_vector
   .. automethod:: _make_opt_data_dropped
   .. automethod:: _make_opt_timestamp
   .. automethod:: _make_opt_timestamp_echo
   .. automethod:: _make_opt_elapsed_time
   .. automethod:: _make_opt_data_checksum

   .. autoattribute:: __proto__
      :no-value:
   .. autoattribute:: __proto_key__
      :no-value:
   .. autoattribute:: __option__
      :no-value:

   .. automethod:: __index__

.. autodata:: pcapkit.protocols.transport.dccp.DCCP_MAX_HEADER_LEN

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.transport.dccp

.. autodata:: pcapkit.protocols.schema.transport.dccp.DCCP_MIN_HEADER_LEN

.. autodata:: pcapkit.protocols.schema.transport.dccp.DCCP_SINGLE_OCTET_OPTION_MAX

.. autodata:: pcapkit.protocols.schema.transport.dccp.ACK_TYPES
   :no-value:

.. autodata:: pcapkit.protocols.schema.transport.dccp.SERVICE_TYPES
   :no-value:

.. autodata:: pcapkit.protocols.schema.transport.dccp.RESET_TYPE

.. autofunction:: pcapkit.protocols.schema.transport.dccp.header_length

.. autoclass:: pcapkit.protocols.schema.transport.dccp.DCCP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.Coverage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.TypeField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.Padding
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.Mandatory
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.SlowReceiver
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.Change
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.Confirm
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.InitCookie
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.NDPCount
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.AckVector
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.DataDropped
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.Timestamp
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.TimestampEcho
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.ElapsedTime
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.dccp.DataChecksum
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.transport.dccp

.. autoclass:: pcapkit.protocols.data.transport.dccp.DCCP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.Padding
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.Mandatory
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.SlowReceiver
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.Change
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.Confirm
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.InitCookie
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.NDPCount
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.AckVector
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.AckVectorRun
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.DataDropped
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.DataDroppedBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.Timestamp
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.TimestampEcho
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.ElapsedTime
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.dccp.DataChecksum
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Datagram_Congestion_Control_Protocol
