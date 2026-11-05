HIP - Host Identity Protocol
============================

.. module:: pcapkit.protocols.internet.hip
.. module:: pcapkit.protocols.internet.hip.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.internet.hip.Locator``, with no alias: it is in this module, and
   :mod:`pcapkit.protocols.internet.hip` exports the protocol class alone
   (:issue:`2534`).

:mod:`pcapkit.protocols.internet.hip.protocol` contains
:class:`~pcapkit.protocols.internet.hip.protocol.HIP` only,
which implements the extractor for Host Identity
Protocol (HIP) [*]_, whose structure is:

======= ========= ====================== ==================================
Octets      Bits        Name                    Description
======= ========= ====================== ==================================
  0           0   ``hip.next``              Next Header
  1           8   ``hip.length``            Header Length
  2          16   ``hip.packet_fixed``      Fixed Bit (``0``)
  2          17   ``hip.type``              Packet Type
  3          24   ``hip.version``           Version
  3          28   ``hip.reserved``          Reserved
  3          31   ``hip.version_fixed``     Fixed Bit (``1``)
  4          32   ``hip.chksum``            Checksum
  6          48   ``hip.control``           Controls
  8          64   ``hip.shit``              Sender's Host Identity Tag
  24        192   ``hip.rhit``              Receiver's Host Identity Tag
  40        320   ``hip.parameters``        HIP Parameters
======= ========= ====================== ==================================

.. autoclass:: pcapkit.protocols.internet.hip.protocol.HIP
   :no-members:
   :show-inheritance:

   .. autoattribute:: __parameter__
      :no-value:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register_parameter
   .. automethod:: id

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _read_hip_param
   .. automethod:: _make_hip_param
   .. automethod:: _read_param_unassigned
   .. automethod:: _read_param_esp_info
   .. automethod:: _read_param_r1_counter
   .. automethod:: _read_param_locator_set
   .. automethod:: _read_param_puzzle
   .. automethod:: _read_param_solution
   .. automethod:: _read_param_seq
   .. automethod:: _read_param_ack
   .. automethod:: _read_param_dh_group_list
   .. automethod:: _read_param_diffie_hellman
   .. automethod:: _read_param_hip_transform
   .. automethod:: _read_param_hip_cipher
   .. automethod:: _read_param_nat_traversal_mode
   .. automethod:: _read_param_transaction_pacing
   .. automethod:: _read_param_encrypted
   .. automethod:: _read_param_host_id
   .. automethod:: _read_param_hit_suite_list
   .. automethod:: _read_param_cert
   .. automethod:: _read_param_notification
   .. automethod:: _read_param_echo_request_signed
   .. automethod:: _read_param_reg_info
   .. automethod:: _read_param_reg_request
   .. automethod:: _read_param_reg_response
   .. automethod:: _read_param_reg_failed
   .. automethod:: _read_param_reg_from
   .. automethod:: _read_param_echo_response_signed
   .. automethod:: _read_param_transport_format_list
   .. automethod:: _read_param_esp_transform
   .. automethod:: _read_param_seq_data
   .. automethod:: _read_param_ack_data
   .. automethod:: _read_param_payload_mic
   .. automethod:: _read_param_transaction_id
   .. automethod:: _read_param_overlay_id
   .. automethod:: _read_param_route_dst
   .. automethod:: _read_param_hip_transport_mode
   .. automethod:: _read_param_hip_mac
   .. automethod:: _read_param_hip_mac_2
   .. automethod:: _read_param_hip_signature_2
   .. automethod:: _read_param_hip_signature
   .. automethod:: _read_param_echo_response_unsigned
   .. automethod:: _read_param_echo_request_unsigned
   .. automethod:: _read_param_relay_from
   .. automethod:: _read_param_relay_to
   .. automethod:: _read_param_overlay_ttl
   .. automethod:: _read_param_route_via
   .. automethod:: _read_param_from
   .. automethod:: _read_param_rvs_hmac
   .. automethod:: _read_param_via_rvs
   .. automethod:: _read_param_relay_hmac
   .. automethod:: _make_param_unassigned
   .. automethod:: _make_param_esp_info
   .. automethod:: _make_param_r1_counter
   .. automethod:: _make_param_locator_set
   .. automethod:: _make_param_puzzle
   .. automethod:: _make_param_solution
   .. automethod:: _make_param_seq
   .. automethod:: _make_param_ack
   .. automethod:: _make_param_dh_group_list
   .. automethod:: _make_param_diffie_hellman
   .. automethod:: _make_param_hip_transform
   .. automethod:: _make_param_hip_cipher
   .. automethod:: _make_param_nat_traversal_mode
   .. automethod:: _make_param_transaction_pacing
   .. automethod:: _make_param_encrypted
   .. automethod:: _make_param_host_id
   .. automethod:: _make_param_hit_suite_list
   .. automethod:: _make_param_cert
   .. automethod:: _make_param_notification
   .. automethod:: _make_param_echo_request_signed
   .. automethod:: _make_param_reg_info
   .. automethod:: _make_param_reg_request
   .. automethod:: _make_param_reg_response
   .. automethod:: _make_param_reg_failed
   .. automethod:: _make_param_reg_from
   .. automethod:: _make_param_echo_response_signed
   .. automethod:: _make_param_transport_format_list
   .. automethod:: _make_param_esp_transform
   .. automethod:: _make_param_seq_data
   .. automethod:: _make_param_ack_data
   .. automethod:: _make_param_payload_mic
   .. automethod:: _make_param_transaction_id
   .. automethod:: _make_param_overlay_id
   .. automethod:: _make_param_route_dst
   .. automethod:: _make_param_hip_transport_mode
   .. automethod:: _make_param_hip_mac
   .. automethod:: _make_param_hip_mac_2
   .. automethod:: _make_param_hip_signature_2
   .. automethod:: _make_param_hip_signature
   .. automethod:: _make_param_echo_response_unsigned
   .. automethod:: _make_param_echo_request_unsigned
   .. automethod:: _make_param_relay_from
   .. automethod:: _make_param_relay_to
   .. automethod:: _make_param_overlay_ttl
   .. automethod:: _make_param_route_via
   .. automethod:: _make_param_from
   .. automethod:: _make_param_rvs_hmac
   .. automethod:: _make_param_via_rvs
   .. automethod:: _make_param_relay_hmac
   .. automethod:: _make_hip_param_data

Type Stubs
----------

.. autoclass:: pcapkit.protocols.internet.hip.protocol.Locator
   :members:
   :show-inheritance:

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.hip.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.hip``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.hip.schema.HIP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.Parameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.UnassignedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.ESPInfoParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.R1CounterParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.LocatorSetParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.Locator
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.LocatorData
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.PuzzleParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.SolutionParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.SEQParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.ACKParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.DHGroupListParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.DiffieHellmanParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.HIPTransformParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.HIPCipherParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.NATTraversalModeParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.TransactionPacingParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.EncryptedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.HostIDParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.HostIdentity
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.ECDSACurveHostIdentity
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.ECDSALowCurveHostIdentity
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.EdDSACurveHostIdentity
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.HITSuiteListParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.CertParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.NotificationParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.EchoRequestSignedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.RegInfoParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.RegRequestParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.RegResponseParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.RegFailedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.RegFromParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.EchoResponseSignedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.TransportFormatListParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.ESPTransformParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.SeqDataParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.AckDataParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.PayloadMICParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.TransactionIDParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.OverlayIDParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.RouteDstParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.HIPTransportModeParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.HIPMACParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.HIPMAC2Parameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.HIPSignature2Parameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.HIPSignatureParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.EchoRequestUnsignedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.EchoResponseUnsignedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.RelayFromParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.RelayToParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.OverlayTTLParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.RouteViaParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.FromParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.RVSHMACParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.ViaRVSParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.RelayHMACParameter
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.internet.hip.schema.PacketType
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.VersionType
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.ControlsType
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.LocatorFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.DIData
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.schema.RouteFlags
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.internet.hip.schema.locator_value_selector
.. autofunction:: pcapkit.protocols.internet.hip.schema.host_id_hi_selector
.. autofunction:: pcapkit.protocols.internet.hip.schema.registration_type_list_len
.. autofunction:: pcapkit.protocols.internet.hip.schema.reg_info_list_len
.. autofunction:: pcapkit.protocols.internet.hip.schema.two_octet_prefix_list_len
.. autofunction:: pcapkit.protocols.internet.hip.schema.transport_format_list_len
.. autofunction:: pcapkit.protocols.internet.hip.schema.encrypted_data_len
.. autofunction:: pcapkit.protocols.internet.hip.schema.parameter_total_len
.. autofunction:: pcapkit.protocols.internet.hip.schema.parameter_padding_len
.. autofunction:: pcapkit.protocols.internet.hip.schema.locator_set_len_callback
.. autofunction:: pcapkit.protocols.internet.hip.schema.locator_set_padding_len

.. autodata:: pcapkit.protocols.internet.hip.schema.LOCATOR_SET_LEN

Data Models
-----------

.. module:: pcapkit.protocols.internet.hip.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.internet.hip``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.hip.data.HIP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.Control
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.Parameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.UnassignedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.ESPInfoParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.R1CounterParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.LocatorSetParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.Locator
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.LocatorData
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.PuzzleParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.SolutionParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.SEQParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.ACKParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.DHGroupListParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.DiffieHellmanParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.HIPTransformParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.HIPCipherParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.NATTraversalModeParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.TransactionPacingParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.EncryptedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.HostIDParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.HostIdentity
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.HITSuiteListParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.CertParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.NotificationParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.EchoRequestSignedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.RegInfoParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.Lifetime
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.RegRequestParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.RegResponseParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.RegFailedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.RegFromParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.EchoResponseSignedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.TransportFormatListParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.ESPTransformParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.SeqDataParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.AckDataParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.PayloadMICParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.TransactionIDParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.OverlayIDParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.RouteDstParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.Flags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.HIPTransportModeParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.HIPMACParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.HIPMAC2Parameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.HIPSignature2Parameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.HIPSignatureParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.EchoRequestUnsignedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.EchoResponseUnsignedParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.RelayFromParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.RelayToParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.OverlayTTLParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.RouteViaParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.FromParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.RVSHMACParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.ViaRVSParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hip.data.RelayHMACParameter
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Host_Identity_Protocol
