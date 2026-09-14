SCTP - Stream Control Transmission Protocol
===========================================

.. module:: pcapkit.protocols.transport.sctp

:mod:`pcapkit.protocols.transport.sctp` contains
:class:`~pcapkit.protocols.transport.sctp.SCTP` only,
which implements extractor for Stream Control
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

.. autoclass:: pcapkit.protocols.transport.sctp.SCTP
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
   .. autoattribute:: __chunk__
      :no-value:
   .. autoattribute:: __parameter__
      :no-value:
   .. autoattribute:: __cause__
      :no-value:

   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.transport.sctp

.. autoclass:: pcapkit.protocols.schema.transport.sctp.SCTP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.Chunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.UnknownChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.DATAChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.INITChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.INITACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.SACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.HeartbeatChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.HeartbeatACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.AbortChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.ShutdownChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.ShutdownACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.ErrorChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.CookieEchoChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.CookieACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.ShutdownCompleteChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.GapAckBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.Parameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.UnknownParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.HeartbeatInfoParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.IPv4AddressParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.IPv6AddressParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.StateCookieParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.UnrecognizedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.CookiePreservativeParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.HostNameAddressParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.SupportedAddressTypesParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.ErrorCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.UnknownCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.InvalidStreamIdentifierCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.MissingMandatoryParameterCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.StaleCookieCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.OutOfResourceCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.UnresolvableAddressCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.UnrecognizedChunkTypeCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.InvalidMandatoryParameterCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.UnrecognizedParametersCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.NoUserDataCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.CookieReceivedWhileShuttingDownCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.RestartOfAnAssociationWithNewAddressesCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.UserInitiatedAbortCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.ProtocolViolationCause
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.schema.transport.sctp.DATAChunkFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.transport.sctp.TBitFlags
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.schema.transport.sctp.padding_length
.. autofunction:: pcapkit.protocols.schema.transport.sctp.nested_length

Data Models
-----------

.. module:: pcapkit.protocols.data.transport.sctp

.. autoclass:: pcapkit.protocols.data.transport.sctp.SCTP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.DATAChunkFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.TBitFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.GapAckBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.Chunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.UnknownChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.DATAChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.INITChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.INITACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.SACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.HeartbeatChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.HeartbeatACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.AbortChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.ShutdownChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.ShutdownACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.ErrorChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.CookieEchoChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.CookieACKChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.ShutdownCompleteChunk
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.Parameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.UnknownParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.HeartbeatInfoParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.IPv4AddressParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.IPv6AddressParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.StateCookieParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.UnrecognizedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.CookiePreservativeParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.HostNameAddressParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.SupportedAddressTypesParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.ErrorCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.UnknownCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.InvalidStreamIdentifierCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.MissingMandatoryParameterCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.StaleCookieCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.OutOfResourceCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.UnresolvableAddressCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.UnrecognizedChunkTypeCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.InvalidMandatoryParameterCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.UnrecognizedParametersCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.NoUserDataCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.CookieReceivedWhileShuttingDownCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.RestartOfAnAssociationWithNewAddressesCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.UserInitiatedAbortCause
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.transport.sctp.ProtocolViolationCause
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol
