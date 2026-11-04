DCCP - Datagram Congestion Control Protocol
===========================================

.. module:: pcapkit.protocols.transport.dccp
.. module:: pcapkit.protocols.transport.dccp.protocol

:mod:`pcapkit.protocols.transport.dccp.protocol` contains
:class:`~pcapkit.protocols.transport.dccp.protocol.DCCP` only,
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

.. autoclass:: pcapkit.protocols.transport.dccp.protocol.DCCP
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

.. autodata:: pcapkit.protocols.transport.dccp.protocol.DCCP_MAX_HEADER_LEN

Header Schemas
--------------

.. module:: pcapkit.protocols.transport.dccp.schema

.. autodata:: pcapkit.protocols.transport.dccp.schema.DCCP_MIN_HEADER_LEN

.. autodata:: pcapkit.protocols.transport.dccp.schema.DCCP_SINGLE_OCTET_OPTION_MAX

.. autodata:: pcapkit.protocols.transport.dccp.schema.ACK_TYPES
   :no-value:

.. autodata:: pcapkit.protocols.transport.dccp.schema.SERVICE_TYPES
   :no-value:

.. autodata:: pcapkit.protocols.transport.dccp.schema.RESET_TYPE

.. autofunction:: pcapkit.protocols.transport.dccp.schema.header_length

.. autoclass:: pcapkit.protocols.transport.dccp.schema.DCCP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.Coverage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.TypeField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.Padding
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.Mandatory
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.SlowReceiver
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.Change
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.Confirm
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.InitCookie
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.NDPCount
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.AckVector
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.DataDropped
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.Timestamp
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.TimestampEcho
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.ElapsedTime
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.schema.DataChecksum
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.transport.dccp.data

.. autoclass:: pcapkit.protocols.transport.dccp.data.DCCP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.Padding
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.Mandatory
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.SlowReceiver
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.Change
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.Confirm
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.InitCookie
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.NDPCount
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.AckVector
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.AckVectorRun
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.DataDropped
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.DataDroppedBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.Timestamp
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.TimestampEcho
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.ElapsedTime
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.dccp.data.DataChecksum
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Datagram_Congestion_Control_Protocol
