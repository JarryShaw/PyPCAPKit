HIP - Host Identity Protocol
============================

.. module:: pcapkit.protocols.internet.hip
.. module:: pcapkit.protocols.internet.hip.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.internet.hip.Locator``, with no alias: it is in this module, and
   :mod:`pcapkit.protocols.internet.hip` exports the protocol class alone
   (:issue:`2534`).

:mod:`pcapkit.protocols.internet.hip.protocol` contains
:class:`~pcapkit.protocols.internet.hip.protocol.HIP`,
which implements the extractor for Host Identity
Protocol (HIP) [*]_, and the keys it verifies HMACs and
signatures with (`Verifying HMACs and Signatures`_). The
HIP structure:

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

   .. rubric:: Defaults

   .. autoattribute:: __parameter__
      :no-value:

   .. rubric:: Properties

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. rubric:: Methods

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register_parameter
   .. automethod:: id

   .. rubric:: Data Models

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. rubric:: Utilities

   .. automethod:: _make_data
   .. automethod:: _read_hip_param
   .. automethod:: _make_hip_param
   .. automethod:: _verify_hip_param
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
   .. automethod:: _verify_hip_mac
   .. automethod:: _verify_hip_signature
   .. automethod:: _auth_scope
   .. automethod:: _verify_pseudo_checksum

Verifying HMACs and Signatures
------------------------------

``HIP_MAC``, ``HIP_MAC_2``, ``HIP_SIGNATURE`` and ``HIP_SIGNATURE_2`` are verified
with keys the caller supplies through the protocol-keyed context channel of
:mod:`pcapkit.corekit.context` (:rfc:`7401#section-6.4`). Each records the outcome as
its ``hmac_status`` or ``signature_status``, and nothing else of the parse changes:

.. code-block:: python

   import pcapkit
   from pcapkit.const.hip.parameter import Parameter
   from pcapkit.protocols.internet.hip.protocol import (HIPAssociation, HIPContext,
                                                        HIPIdentity)

   r1 = ...  # the HIP layer of an R1 packet, parsed without a context
   context = HIPContext(
       HIPIdentity(r1.info.shit, r1.info.parameters[Parameter.HOST_ID]),
       HIPAssociation(initiator_hit, responder_hit,
                      integrity_gl=bytes.fromhex('...'), integrity_lg=bytes.fromhex('...')),
   )
   extraction = pcapkit.extract('hip.pcap', context=context)

An HMAC needs the association's integrity keys, or the Diffie-Hellman session key
they derive from (:meth:`HIPAssociation.from_keymat
<pcapkit.protocols.internet.hip.protocol.HIPAssociation.from_keymat>`), and uses only
the standard library. ``HIP_MAC_2`` also needs the Responder's ``HOST_ID``, and a
signature its sender's. Verifying a signature needs the optional |cryptography|_
dependency:

============== ================================ ============ ====================================
Algorithm      Hash                             Implemented  Encoding
============== ================================ ============ ====================================
RSA            SHA-256, RSASSA-PSS              yes          :rfc:`3110` key
DSA            SHA-256                          yes          :rfc:`2536` key and signature
ECDSA          SHA-384                          yes          NIST P-256 and P-384, :rfc:`6090` key
ECDSA_LOW      SHA-1                            **no**       SECP160R1, which |cryptography|_ lacks
EdDSA          none, :rfc:`8032`                yes          EdDSA25519 and EdDSA448, not the
                                                             pre-hashed curves
============== ================================ ============ ====================================

A signature digests with the hash of its Host Identity's HIT Suite, as Table 10 of
:rfc:`7401#section-5.2.10` groups them, and EdDSA (:rfc:`9374`) with none of its own.
Only HIP version 2 is verified.

.. autoclass:: pcapkit.protocols.internet.hip.protocol.HIPContext
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: identities
   .. autoproperty:: associations

   .. rubric:: Methods

   .. automethod:: protocol
   .. automethod:: register
   .. automethod:: match_identity
   .. automethod:: match_association

   .. rubric:: Data Models

   .. automethod:: __repr__

.. autoclass:: pcapkit.protocols.internet.hip.protocol.HIPIdentity
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: hit
   .. autoproperty:: host_id

   .. rubric:: Methods

   .. automethod:: verify

   .. rubric:: Data Models

   .. automethod:: __repr__

   .. rubric:: Utilities

   .. automethod:: _verify_signature
   .. automethod:: _verify_ecdsa
   .. automethod:: _rsa_numbers
   .. automethod:: _dsa_numbers
   .. automethod:: _ecdsa_points

.. autoclass:: pcapkit.protocols.internet.hip.protocol.HIPAssociation
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: initiator
   .. autoproperty:: responder
   .. autoproperty:: suite
   .. autoproperty:: integrity_gl
   .. autoproperty:: integrity_lg

   .. rubric:: Methods

   .. automethod:: from_keymat
   .. automethod:: matches
   .. automethod:: compute_hmac

   .. rubric:: Data Models

   .. automethod:: __repr__

   .. rubric:: Utilities

   .. automethod:: _resolve_suite
   .. automethod:: _hkdf

.. autoclass:: pcapkit.protocols.internet.hip.protocol.HIPAuthStatus
   :members:
   :show-inheritance:

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

Constants
---------

.. module:: pcapkit.protocols.internet.hip.const

.. versionadded:: 1.7.0

.. autodata:: pcapkit.protocols.internet.hip.const.LOCATOR_SET_LEN
.. autodata:: pcapkit.protocols.internet.hip.const.ORCHID_PREFIX
.. autodata:: pcapkit.protocols.internet.hip.const.HIT_SUITE_HASH
.. autodata:: pcapkit.protocols.internet.hip.const.HI_ALGORITHM_SUITE
.. autodata:: pcapkit.protocols.internet.hip.const.CIPHER_KEY_LEN
.. autodata:: pcapkit.protocols.internet.hip.const.ECDSA_CURVE_LEN
.. autodata:: pcapkit.protocols.internet.hip.const.EDDSA_CURVE_LEN

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Host_Identity_Protocol
