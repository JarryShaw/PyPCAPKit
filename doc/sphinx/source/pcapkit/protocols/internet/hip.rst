HIP - Host Identity Protocol
============================

.. module:: pcapkit.protocols.internet.hip
.. module:: pcapkit.protocols.data.internet.hip

:mod:`pcapkit.protocols.internet.hip` contains
:class:`~pcapkit.protocols.internet.hip.HIP` only,
which implements extractor for Host Identity
Protocol (HIP) [*]_, whose structure is described
as below:

======= ========= ====================== ==================================
Octets      Bits        Name                    Description
======= ========= ====================== ==================================
  0           0   ``hip.next``              Next Header
  1           8   ``hip.length``            Header Length
  2          16                             Reserved (``\x00``)
  2          17   ``hip.type``              Packet Type
  3          24   ``hip.version``           Version
  3          28                             Reserved
  3          31                             Reserved (``\x01``)
  4          32   ``hip.chksum``            Checksum
  6          48   ``hip.control``           Controls
  8          64   ``hip.shit``              Sender's Host Identity Tag
  24        192   ``hip.rhit``              Receiver's Host Identity Tag
  40        320   ``hip.parameters``        HIP Parameters
======= ========= ====================== ==================================

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.internet.hip.HIP
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _read_hip_param
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
   .. automethod:: _read_param_echo_request_unsigned
   .. automethod:: _read_param_echo_response_unsigned
   .. automethod:: _read_param_relay_from
   .. automethod:: _read_param_relay_to
   .. automethod:: _read_param_overlay_ttl
   .. automethod:: _read_param_route_via
   .. automethod:: _read_param_from
   .. automethod:: _read_param_rvs_hmac
   .. automethod:: _read_param_via_rvs
   .. automethod:: _read_param_relay_hmac

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.internet.hip.HIP(next, length, type, version, chksum, control, shit, rhit)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: next
   .. autoattribute:: length
   .. autoattribute:: type
   .. autoattribute:: version
   .. autoattribute:: chksum
   .. autoattribute:: control
   .. autoattribute:: shit
   .. autoattribute:: rhit
   .. autoattribute:: parameters

.. autoclass:: pcapkit.protocols.data.internet.hip.Control(anonymous)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: anonymous

.. autoclass:: pcapkit.protocols.data.internet.hip.Parameter(type, critical, length)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: type
   .. autoattribute:: critical
   .. autoattribute:: length

.. autoclass:: pcapkit.protocols.data.internet.hip.UnassignedParameter(type, critical, length, contents)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: contents

.. autoclass:: pcapkit.protocols.data.internet.hip.ESPInfoParameter(type, critical, length, index, old_spi, new_spi)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: index
   .. autoattribute:: old_spi
   .. autoattribute:: new_spi

.. autoclass:: pcapkit.protocols.data.internet.hip.R1CounterParameter(type, critical, length, counter)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: counter

.. autoclass:: pcapkit.protocols.data.internet.hip.LocatorSetParameter(type, critical, length, locator_set)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: locator_set

.. autoclass:: pcapkit.protocols.data.internet.hip.Locator(traffic, type, length, preferred, lifetime, locator)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: traffic
   .. autoattribute:: type
   .. autoattribute:: length
   .. autoattribute:: preferred
   .. autoattribute:: lifetime
   .. autoattribute:: locator

.. autoclass:: pcapkit.protocols.data.internet.hip.LocatorData(spi, ip)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: spi
   .. autoattribute:: ip

.. autoclass:: pcapkit.protocols.data.internet.hip.PuzzleParameter(type, critical, length, index, lifetime, opaque, random)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: index
   .. autoattribute:: lifetime
   .. autoattribute:: opaque
   .. autoattribute:: random

.. autoclass:: pcapkit.protocols.data.internet.hip.SolutionParameter(type, critical, length, index, lifetime, opaque, random, solution)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: index
   .. autoattribute:: lifetime
   .. autoattribute:: opaque
   .. autoattribute:: random
   .. autoattribute:: solution

.. autoclass:: pcapkit.protocols.data.internet.hip.SEQParameter(type, critical, length, id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: id

.. autoclass:: pcapkit.protocols.data.internet.hip.ACKParameter(type, critical, length, update_id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: update_id

.. autoclass:: pcapkit.protocols.data.internet.hip.DHGroupListParameter(type, critical, length, group_id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: group_id

.. autoclass:: pcapkit.protocols.data.internet.hip.DiffieHellmanParameter(type, critical, length, group_id, pub_len, pub_val)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: group_id
   .. autoattribute:: pub_len
   .. autoattribute:: pub_val

.. autoclass:: pcapkit.protocols.data.internet.hip.HIPTransformParameter(type, critical, length, suite_id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: suite_id

.. autoclass:: pcapkit.protocols.data.internet.hip.HIPCipherParameter(type, critical, length, cipher_id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: cipher_id

.. autoclass:: pcapkit.protocols.data.internet.hip.NATTraversalModeParameter(type, critical, length, mode_id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: mode_id

.. autoclass:: pcapkit.protocols.data.internet.hip.TransactionPacingParameter(type, critical, length, min_ta)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: min_ta

.. autoclass:: pcapkit.protocols.data.internet.hip.EncryptedParameter(type, critical, length, raw)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: raw

.. autoclass:: pcapkit.protocols.data.internet.hip.HostIDParameter(type, critical, length, hi_len, di_type, di_len, algorithm, hi, di)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: hi_len
   .. autoattribute:: di_type
   .. autoattribute:: di_len
   .. autoattribute:: algorithm
   .. autoattribute:: hi
   .. autoattribute:: di

.. autoclass:: pcapkit.protocols.data.internet.hip.HostIdentity(curve, pubkey)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: curve
   .. autoattribute:: pubkey

.. autoclass:: pcapkit.protocols.data.internet.hip.HITSuiteListParameter(type, critical, length, suite_id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: suite_id

.. autoclass:: pcapkit.protocols.data.internet.hip.CertParameter(type, critical, length, cert_group, cert_count, cert_id, cert_type, cert)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: cert_group
   .. autoattribute:: cert_count
   .. autoattribute:: cert_id
   .. autoattribute:: cert_type
   .. autoattribute:: cert

.. autoclass:: pcapkit.protocols.data.internet.hip.NotificationParameter(type, critical, length, msg_type, msg)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: msg_type
   .. autoattribute:: msg

.. autoclass:: pcapkit.protocols.data.internet.hip.EchoRequestSignedParameter(type, critical, length, opaque)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: opaque

.. autoclass:: pcapkit.protocols.data.internet.hip.RegInfoParameter(type, critical, length, lifetime, reg_type)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: lifetime
   .. autoattribute:: reg_type

.. autoclass:: pcapkit.protocols.data.internet.hip.Lifetime(min, max)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: min
   .. autoattribute:: max

.. autoclass:: pcapkit.protocols.data.internet.hip.RegRequestParameter(type, critical, length, lifetime, reg_type)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: lifetime
   .. autoattribute:: reg_type

.. autoclass:: pcapkit.protocols.data.internet.hip.RegResponseParameter(type, critical, length, lifetime, reg_type)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: lifetime
   .. autoattribute:: reg_type

.. autoclass:: pcapkit.protocols.data.internet.hip.RegFailedParameter(type, critical, length, lifetime, reg_type)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: lifetime
   .. autoattribute:: reg_type

.. autoclass:: pcapkit.protocols.data.internet.hip.RegFromParameter(type, critical, length, port, protocol, address)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: port
   .. autoattribute:: protocol
   .. autoattribute:: address

.. autoclass:: pcapkit.protocols.data.internet.hip.EchoResponseSignedParameter(type, critical, length, opaque)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: opaque

.. autoclass:: pcapkit.protocols.data.internet.hip.TransportFormatListParameter(type, critical, length, tf_type)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: tf_type

.. autoclass:: pcapkit.protocols.data.internet.hip.ESPTransformParameter(type, critical, length, suite_id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: suite_id

.. autoclass:: pcapkit.protocols.data.internet.hip.SeqDataParameter(type, critical, length, seq)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: seq

.. autoclass:: pcapkit.protocols.data.internet.hip.AckDataParameter(type, critical, length, ack)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: ack

.. autoclass:: pcapkit.protocols.data.internet.hip.PayloadMICParameter(type, critical, length, next, payload, mic)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: next
   .. autoattribute:: payload
   .. autoattribute:: mic

.. autoclass:: pcapkit.protocols.data.internet.hip.TransactionIDParameter(type, critical, length, id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: id

.. autoclass:: pcapkit.protocols.data.internet.hip.OverlayIDParameter(type, critical, length, id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: id

.. autoclass:: pcapkit.protocols.data.internet.hip.RouteDstParameter(type, critical, length, flags, hit)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: hit

.. autoclass:: pcapkit.protocols.data.internet.hip.Flags(symmetric, must_follow)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: symmetric
   .. autoattribute:: must_follow

.. autoclass:: pcapkit.protocols.data.internet.hip.HIPTransportModeParameter(type, critical, length, port, mode_id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: port
   .. autoattribute:: mode_id

.. autoclass:: pcapkit.protocols.data.internet.hip.HIPMACParameter(type, critical, length, hmac)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: hmac

.. autoclass:: pcapkit.protocols.data.internet.hip.HIPMAC2Parameter(type, critical, length, hmac)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: hmac

.. autoclass:: pcapkit.protocols.data.internet.hip.HIPSignature2Parameter(type, critical, length, algorithm, signature)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: algorithm
   .. autoattribute:: signature

.. autoclass:: pcapkit.protocols.data.internet.hip.HIPSignatureParameter(type, critical, length, algorithm, signature)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: algorithm
   .. autoattribute:: signature

.. autoclass:: pcapkit.protocols.data.internet.hip.EchoRequestUnsignedParameter(type, critical, length, opaque)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: opaque

.. autoclass:: pcapkit.protocols.data.internet.hip.EchoResponseUnsignedParameter(type, critical, length, opaque)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: opaque

.. autoclass:: pcapkit.protocols.data.internet.hip.RelayFromParameter(type, critical, length, port, protocol, address)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: port
   .. autoattribute:: protocol
   .. autoattribute:: address

.. autoclass:: pcapkit.protocols.data.internet.hip.RelayToParameter(type, critical, length, port, protocol, address)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: port
   .. autoattribute:: protocol
   .. autoattribute:: address

.. autoclass:: pcapkit.protocols.data.internet.hip.OverlayTTLParameter(type, critical, length, ttl)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: ttl

.. autoclass:: pcapkit.protocols.data.internet.hip.RouteViaParameter(type, critical, length, flags, hit)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: hit

.. autoclass:: pcapkit.protocols.data.internet.hip.FromParameter(type, critical, length, address)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: address

.. autoclass:: pcapkit.protocols.data.internet.hip.RVSHMACParameter(type, critical, length, hmac)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: hmac

.. autoclass:: pcapkit.protocols.data.internet.hip.ViaRVSParameter(type, critical, length, address)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: address

.. autoclass:: pcapkit.protocols.data.internet.hip.RelayHMACParameter(type, critical, length, hmac)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: hmac

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Host_Identity_Protocol
