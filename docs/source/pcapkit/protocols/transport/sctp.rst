SCTP - Stream Control Transmission Protocol
===========================================

.. module:: pcapkit.protocols.transport.sctp
.. module:: pcapkit.protocols.transport.sctp.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.transport.sctp.CRC32C_TABLE``, with no alias: it is in this
   module, and :mod:`pcapkit.protocols.transport.sctp` exports the protocol class alone
   (:issue:`2534`).

:mod:`pcapkit.protocols.transport.sctp.protocol` contains
:class:`~pcapkit.protocols.transport.sctp.protocol.SCTP` only,
which implements the extractor for Stream Control
Transmission Protocol (SCTP) [*]_, whose structure is
described as below:

======= ========= ========================= =======================================
Octets      Bits        Name                    Description
======= ========= ========================= =======================================
  0           0   ``sctp.srcport``          Source Port
  2          16   ``sctp.dstport``          Destination Port
  4          32   ``sctp.vtag``             Verification Tag
  8          64   ``sctp.chksum``           Checksum (CRC32c)
  12         96   ``sctp.chunks``           Chunks
======= ========= ========================= =======================================

.. autoclass:: pcapkit.protocols.transport.sctp.protocol.SCTP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: src
   .. autoproperty:: dst
   .. autoproperty:: ppid
   .. autoproperty:: checksum_valid

   .. automethod:: read
   .. automethod:: make

   .. automethod:: register
   .. automethod:: register_chunk
   .. automethod:: register_parameter
   .. automethod:: register_cause

   .. automethod:: crc32c
   .. automethod:: calculate_checksum
   .. automethod:: validate_checksum

   .. automethod:: _make_data
   .. automethod:: _get_payload
   .. automethod:: _decode_next_layer

   .. automethod:: _read_sctp_chunks
   .. automethod:: _make_sctp_chunks
   .. automethod:: _make_sctp_chunk
   .. automethod:: _read_sctp_parameters
   .. automethod:: _make_sctp_parameters
   .. automethod:: _make_sctp_parameter
   .. automethod:: _read_sctp_causes
   .. automethod:: _make_sctp_causes
   .. automethod:: _make_sctp_cause
   .. automethod:: _make_param_types

   .. automethod:: _read_chunk_donone
   .. automethod:: _read_chunk_data
   .. automethod:: _read_chunk_init
   .. automethod:: _read_chunk_init_ack
   .. automethod:: _read_chunk_sack
   .. automethod:: _read_chunk_heartbeat
   .. automethod:: _read_chunk_heartbeat_ack
   .. automethod:: _read_chunk_abort
   .. automethod:: _read_chunk_shutdown
   .. automethod:: _read_chunk_shutdown_ack
   .. automethod:: _read_chunk_error
   .. automethod:: _read_chunk_cookie_echo
   .. automethod:: _read_chunk_cookie_ack
   .. automethod:: _read_chunk_shutdown_complete

   .. automethod:: _make_chunk_donone
   .. automethod:: _make_chunk_data
   .. automethod:: _make_chunk_init
   .. automethod:: _make_chunk_init_ack
   .. automethod:: _make_chunk_sack
   .. automethod:: _make_chunk_heartbeat
   .. automethod:: _make_chunk_heartbeat_ack
   .. automethod:: _make_chunk_abort
   .. automethod:: _make_chunk_shutdown
   .. automethod:: _make_chunk_shutdown_ack
   .. automethod:: _make_chunk_error
   .. automethod:: _make_chunk_cookie_echo
   .. automethod:: _make_chunk_cookie_ack
   .. automethod:: _make_chunk_shutdown_complete

   .. automethod:: _read_param_donone
   .. automethod:: _read_param_hbinfo
   .. automethod:: _read_param_ipv4
   .. automethod:: _read_param_ipv6
   .. automethod:: _read_param_cookie
   .. automethod:: _read_param_unrecognized
   .. automethod:: _read_param_preservative
   .. automethod:: _read_param_hostname
   .. automethod:: _read_param_addrtypes

   .. automethod:: _make_param_donone
   .. automethod:: _make_param_hbinfo
   .. automethod:: _make_param_ipv4
   .. automethod:: _make_param_ipv6
   .. automethod:: _make_param_cookie
   .. automethod:: _make_param_unrecognized
   .. automethod:: _make_param_preservative
   .. automethod:: _make_param_hostname
   .. automethod:: _make_param_addrtypes

   .. automethod:: _read_cause_donone
   .. automethod:: _read_cause_invalid_stream
   .. automethod:: _read_cause_missing_param
   .. automethod:: _read_cause_stale_cookie
   .. automethod:: _read_cause_out_of_resource
   .. automethod:: _read_cause_unresolvable_addr
   .. automethod:: _read_cause_unrecognized_chunk
   .. automethod:: _read_cause_invalid_param
   .. automethod:: _read_cause_unrecognized_params
   .. automethod:: _read_cause_no_user_data
   .. automethod:: _read_cause_cookie_shutdown
   .. automethod:: _read_cause_restart_addr
   .. automethod:: _read_cause_user_abort
   .. automethod:: _read_cause_protocol_violation

   .. automethod:: _make_cause_donone
   .. automethod:: _make_cause_invalid_stream
   .. automethod:: _make_cause_missing_param
   .. automethod:: _make_cause_stale_cookie
   .. automethod:: _make_cause_out_of_resource
   .. automethod:: _make_cause_unresolvable_addr
   .. automethod:: _make_cause_unrecognized_chunk
   .. automethod:: _make_cause_invalid_param
   .. automethod:: _make_cause_unrecognized_params
   .. automethod:: _make_cause_no_user_data
   .. automethod:: _make_cause_cookie_shutdown
   .. automethod:: _make_cause_restart_addr
   .. automethod:: _make_cause_user_abort
   .. automethod:: _make_cause_protocol_violation

   .. autoattribute:: __proto__
      :no-value:
   .. autoattribute:: __proto_key__
      :no-value:
   .. autoattribute:: __chunk__
      :no-value:
   .. autoattribute:: __parameter__
      :no-value:
   .. autoattribute:: __cause__
      :no-value:

   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.transport.sctp.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.transport.sctp``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.transport.sctp.schema.SCTP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.Chunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.UnknownChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.DATAChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.INITChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.INITACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.SACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.HeartbeatChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.HeartbeatACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.AbortChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.ShutdownChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.ShutdownACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.ErrorChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.CookieEchoChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.CookieACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.ShutdownCompleteChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.GapAckBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.Parameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.UnknownParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.HeartbeatInfoParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.IPv4AddressParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.IPv6AddressParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.StateCookieParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.UnrecognizedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.CookiePreservativeParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.HostNameAddressParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.SupportedAddressTypesParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.ErrorCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.UnknownCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.InvalidStreamIdentifierCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.MissingMandatoryParameterCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.StaleCookieCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.OutOfResourceCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.UnresolvableAddressCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.UnrecognizedChunkTypeCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.InvalidMandatoryParameterCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.UnrecognizedParametersCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.NoUserDataCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.CookieReceivedWhileShuttingDownCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.RestartOfAnAssociationWithNewAddressesCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.UserInitiatedAbortCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.ProtocolViolationCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.PaddedOptionField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.ChunkListField
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.transport.sctp.schema.DATAChunkFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.schema.TBitFlags
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.transport.sctp.schema.padding_length
.. autofunction:: pcapkit.protocols.transport.sctp.schema.pre_pack_padding
.. autofunction:: pcapkit.protocols.transport.sctp.schema.bounded
.. autofunction:: pcapkit.protocols.transport.sctp.schema.nested_length
.. autofunction:: pcapkit.protocols.transport.sctp.schema.whole_chunks_length

Data Models
-----------

.. module:: pcapkit.protocols.transport.sctp.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.transport.sctp``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.transport.sctp.data.SCTP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.DATAChunkFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.TBitFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.GapAckBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.Chunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.UnknownChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.DATAChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.INITChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.INITACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.SACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.HeartbeatChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.HeartbeatACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.AbortChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.ShutdownChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.ShutdownACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.ErrorChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.CookieEchoChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.CookieACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.ShutdownCompleteChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.Parameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.UnknownParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.HeartbeatInfoParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.IPv4AddressParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.IPv6AddressParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.StateCookieParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.UnrecognizedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.CookiePreservativeParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.HostNameAddressParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.SupportedAddressTypesParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.ErrorCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.UnknownCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.InvalidStreamIdentifierCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.MissingMandatoryParameterCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.StaleCookieCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.OutOfResourceCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.UnresolvableAddressCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.UnrecognizedChunkTypeCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.InvalidMandatoryParameterCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.UnrecognizedParametersCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.NoUserDataCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.CookieReceivedWhileShuttingDownCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.RestartOfAnAssociationWithNewAddressesCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.UserInitiatedAbortCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.sctp.data.ProtocolViolationCause
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol
