# -*- coding: utf-8 -*-
"""data model for HIP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.utilities.compat import NotRequired

if TYPE_CHECKING:
    from datetime import timedelta
    from ipaddress import IPv6Address
    from typing import Optional

    from pcapkit.const.hip.certificate import Certificate
    from pcapkit.const.hip.cipher import Cipher
    from pcapkit.const.hip.di import DITypes
    from pcapkit.const.hip.ecdsa_curve import ECDSACurve
    from pcapkit.const.hip.ecdsa_low_curve import ECDSALowCurve
    from pcapkit.const.hip.eddsa_curve import EdDSACurve
    from pcapkit.const.hip.esp_transform_suite import ESPTransformSuite
    from pcapkit.const.hip.group import Group
    from pcapkit.const.hip.hi_algorithm import HIAlgorithm
    from pcapkit.const.hip.hit_suite import HITSuite
    from pcapkit.const.hip.nat_traversal import NATTraversal
    from pcapkit.const.hip.notify_message import NotifyMessage
    from pcapkit.const.hip.packet import Packet
    from pcapkit.const.hip.parameter import Parameter as Enum_Parameter
    from pcapkit.const.hip.registration import Registration
    from pcapkit.const.hip.registration_failure import RegistrationFailure
    from pcapkit.const.hip.suite import Suite
    from pcapkit.const.hip.transport import Transport
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.corekit.multidict import OrderedMultiDict

__all__ = [
    'HIP', 'Control',

    'LocatorData', 'Locator',
    'HostIdentity',
    'Lifetime',
    'Flags',

    'UnassignedParameter', 'ESPInfoParameter', 'R1CounterParameter',
    'LocatorSetParameter', 'PuzzleParameter', 'SolutionParameter',
    'SEQParameter', 'ACKParameter', 'DHGroupListParameter',
    'DiffieHellmanParameter', 'HIPTransformParameter', 'HIPCipherParameter',
    'NATTraversalModeParameter', 'TransactionPacingParameter', 'EncryptedParameter',
    'HostIDParameter', 'HITSuiteListParameter', 'CertParameter',
    'NotificationParameter', 'EchoRequestSignedParameter', 'RegInfoParameter',
    'RegRequestParameter', 'RegResponseParameter', 'RegFailedParameter',
    'RegFromParameter', 'EchoResponseSignedParameter', 'TransportFormatListParameter',
    'ESPTransformParameter', 'SeqDataParameter', 'AckDataParameter',
    'PayloadMICParameter', 'TransactionIDParameter', 'OverlayIDParameter',
    'RouteDstParameter', 'HIPTransportModeParameter', 'HIPMACParameter',
    'HIPMAC2Parameter', 'HIPSignature2Parameter', 'HIPSignatureParameter',
    'EchoRequestUnsignedParameter', 'EchoResponseUnsignedParameter', 'RelayFromParameter',
    'RelayToParameter', 'RouteViaParameter', 'FromParameter',
    'RVSHMACParameter', 'RelayHMACParameter',
]


@info_final
class Control(Data):
    """Data model for HIP controls."""

    #: Anonymous flag.
    anonymous: 'bool'


class Parameter(Data):
    """Data model for HIP parameter data."""

    #: Parameter type.
    type: 'Enum_Parameter'
    #: Critical flag.
    critical: 'bool'
    #: Content length.
    length: 'int'


@info_final
class HIP(Data):
    """Data model for HIP header."""

    #: Next header.
    next: 'TransType'
    #: Header length.
    length: 'int'
    #: Packet type.
    type: 'Packet'
    #: Version.
    version: 'int'
    #: Checksum.
    chksum: 'bytes'
    #: Control
    control: 'Control'
    #: Sender's host identity tag.
    shit: 'int'
    #: Receiver's host identity tag.
    rhit: 'int'

    #: HIP parameters.
    parameters: 'OrderedMultiDict[Enum_Parameter, Parameter]' = NotRequired  # type: ignore[assignment]


@info_final
class UnassignedParameter(Parameter):
    """Data model for unassigned parameter."""

    #: Content.
    contents: 'bytes'


@info_final
class ESPInfoParameter(Parameter):
    """Data model for HIP ``ESP_INFO`` parameter."""

    #: KEYMAT index.
    index: 'int'
    #: Old SDI.
    old_spi: 'int'
    #: New SDI.
    new_spi: 'int'


@info_final
class R1CounterParameter(Parameter):
    """Data model for HIP ``R1_COUNTER`` parameter."""

    #: R1 counter.
    counter: 'int'


@info_final
class LocatorData(Data):
    """Data model for HIP locator data."""

    #: SPI.
    spi: 'int'
    #: IP address.
    ip: 'IPv6Address'


@info_final
class Locator(Data):
    """Data model for HIP locator."""

    #: Traffic.
    traffic: 'int'
    #: Locator type.
    type: 'int'
    #: Locator length.
    length: 'int'
    #: Preferred flag.
    preferred: 'bool'
    #: Locator lifetime.
    lifetime: 'timedelta'
    #: Locator data.
    locator: 'LocatorData | IPv6Address'


@info_final
class LocatorSetParameter(Parameter):
    """Data model for HIP ``LOCATOR_SET`` parameter."""

    #: Locator set.
    locator_set: 'tuple[Locator, ...]'


@info_final
class PuzzleParameter(Parameter):
    """Data model for HIP ``PUZZLE`` parameter."""

    #: Numeric index.
    index: 'int'
    #: Lifetime.
    lifetime: 'timedelta'
    #: Puzzle data.
    opaque: 'bytes'
    #: Random number.
    random: 'int'


@info_final
class SolutionParameter(Parameter):
    """Data model for HIP ``SOLUTION`` parameter."""

    #: Numeric index.
    index: 'int'
    #: Lifetime.
    lifetime: 'timedelta'
    #: Solution data.
    opaque: 'bytes'
    #: Random number.
    random: 'int'
    #: Puzzle solution.
    solution: 'int'


@info_final
class SEQParameter(Parameter):
    """Data model for HIP ``SEQ`` parameter."""

    #: Unique ID.
    id: 'int'


@info_final
class ACKParameter(Parameter):
    """Data model for HIP ``ACK`` parameter."""

    #: Peer update IDs.
    update_id: 'tuple[int, ...]'


@info_final
class DHGroupListParameter(Parameter):
    """Data model for HIP ``DH_GROUP_LIST`` parameter."""

    #: DH group list.
    group_id: 'tuple[Group, ...]'


@info_final
class DiffieHellmanParameter(Parameter):
    """Data model for HIP ``DIFFIE_HELLMAN`` parameter."""

    #: Group ID.
    group_id: 'Group'
    #: Public value length.
    pub_len: 'int'
    #: Public value.
    pub_val: 'int'


@info_final
class HIPTransformParameter(Parameter):
    """Data model for HIP ``HIP_TRANSFORM`` parameter."""

    #: Suite IDs.
    suite_id: 'tuple[Suite, ...]'


@info_final
class HIPCipherParameter(Parameter):
    """Data model for HIP ``HIP_CIPHER`` parameter."""

    #: Cipher IDs.
    cipher_id: 'tuple[Cipher, ...]'


@info_final
class NATTraversalModeParameter(Parameter):
    """Data model for HIP ``NAT_TRAVERSAL_MODE`` parameter."""

    #: Mode IDs
    mode_id: 'tuple[NATTraversal, ...]'


@info_final
class TransactionPacingParameter(Parameter):
    """Data model for HIP ``TRANSACTION_PACING`` parameter."""

    #: Min TA.
    min_ta: 'int'


@info_final
class EncryptedParameter(Parameter):
    """Data model for HIP ``ENCRYPTED`` parameter."""

    #: Cipher ID.
    cipher: 'Cipher'
    #: Initialization vector.
    iv: 'Optional[bytes]'
    #: Encrypted data.
    data: 'bytes'


@info_final
class HostIdentity(Data):
    """Data model for host identity."""

    #: Curve type.
    curve: 'ECDSACurve | ECDSALowCurve | EdDSACurve'
    #: Public key.
    pubkey: 'bytes'


@info_final
class HostIDParameter(Parameter):
    """Data model for HIP ``HOST_ID`` parameter."""

    #: Host identity length.
    hi_len: 'int'
    #: Domain identifier type.
    di_type: 'DITypes'
    #: Domain identifier length.
    di_len: 'int'
    #: Algorithm type.
    algorithm: 'HIAlgorithm'
    #: Host identity.
    hi: 'HostIdentity | bytes'
    #: Domain identifier.
    di: 'bytes'


@info_final
class HITSuiteListParameter(Parameter):
    """Data model for HIP ``HIST_SUITE_LIST`` parameter."""

    #: Suite IDs.
    suite_id: 'tuple[HITSuite, ...]'


@info_final
class CertParameter(Parameter):
    """Data model for HIP ``CERT`` parameter."""

    #: Certificate group.
    cert_group: 'Group'
    #: Certificate count.
    cert_count: 'int'
    #: Certificate ID.
    cert_id: 'int'
    #: Certificate type.
    cert_type: 'Certificate'
    #: Certificate.
    cert: 'bytes'


@info_final
class NotificationParameter(Parameter):
    """Data model for HIP ``NOTIFICATION`` parameter."""

    #: Notify message type.
    msg_type: 'NotifyMessage'
    #: Notification data.
    msg: 'bytes'


@info_final
class EchoRequestSignedParameter(Parameter):
    """Data model for HIP ``ECHO_REQUEST_SIGNED`` parameter."""

    #: Opaque data.
    opaque: 'bytes'


@info_final
class Lifetime(Data):
    """Data model for registration lifetime."""

    #: Minimum lifetime.
    min: 'timedelta'
    #: Maximum lifetime.
    max: 'timedelta'


@info_final
class RegInfoParameter(Parameter):
    """Data model for HIP ``REG_INFO`` parameter."""

    #: Registration lifetime.
    lifetime: 'Lifetime'
    #: Registration type.
    reg_type: 'tuple[Registration, ...]'


@info_final
class RegRequestParameter(Parameter):
    """Data model for HIP ``REG_REQUEST`` parameter."""

    #: Registration lifetime.
    lifetime: 'timedelta'
    #: Registration type.
    reg_type: 'tuple[Registration, ...]'


@info_final
class RegResponseParameter(Parameter):
    """Data model for HIP ``REG_RESPONSE`` parameter."""

    #: Registration lifetime.
    lifetime: 'timedelta'
    #: Registration type.
    reg_type: 'tuple[Registration, ...]'


@info_final
class RegFailedParameter(Parameter):
    """Data model for HIP ``REG_FAILED`` parameter."""

    #: Registration lifetime.
    lifetime: 'timedelta'
    #: Registration failure type.
    reg_type: 'tuple[RegistrationFailure, ...]'


@info_final
class RegFromParameter(Parameter):
    """Data model for HIP ``REG_FROM`` parameter."""

    #: Port.
    port: 'int'
    #: Protocol.
    protocol: 'TransType'
    #: Address.
    address: 'IPv6Address'


@info_final
class EchoResponseSignedParameter(Parameter):
    """Data model for HIP ``ECHO_RESPONSE_SIGNED`` parameter."""

    #: Opaque data.
    opaque: 'bytes'


@info_final
class TransportFormatListParameter(Parameter):
    """Data model for HIP ``TRANSPORT_FORMAT_LIST`` parameter."""

    #: Transport format list.
    tf_type: 'tuple[Enum_Parameter, ...]'


@info_final
class ESPTransformParameter(Parameter):
    """Data model for HIP ``ESP_TRANSFORM`` parameter."""

    #: ESP transform.
    suite_id: 'tuple[ESPTransformSuite, ...]'


@info_final
class SeqDataParameter(Parameter):
    """Data model for HIP ``SEQ_DATA`` parameter."""

    #: Sequence number.
    seq: 'int'


@info_final
class AckDataParameter(Parameter):
    """Data model for HIP ``ACK_DATA`` parameter."""

    #: Acknowledged sequence number.
    ack: 'tuple[int, ...]'


@info_final
class PayloadMICParameter(Parameter):
    """Data model for HIP ``PAYLOAD_MIC`` parameter."""

    #: Next header
    next: 'TransType'
    #: Payload data.
    payload: 'bytes'
    #: MIC value.
    mic: 'bytes'


@info_final
class TransactionIDParameter(Parameter):
    """Data model for HIP ``TRANSACTION_ID`` parameter."""

    #: Identifier.
    id: 'int'


@info_final
class OverlayIDParameter(Parameter):
    """Data mode HIP ``OVERLAY_ID`` parameter."""

    #: Identifier.
    id: 'int'


@info_final
class Flags(Data):
    """Data model for flags in HIP ``HIP_PARAMETER_FLAGS`` parameter."""

    #: Symmetric flag.
    symmetric: 'bool'
    #: Must follow flag.
    must_follow: 'bool'


@info_final
class RouteDstParameter(Parameter):
    """Data model for HIP ``ROUTE_DST`` parameter."""

    #: Flags.
    flags: 'Flags'
    #: Destination address.
    hit: 'tuple[IPv6Address, ...]'


@info_final
class HIPTransportModeParameter(Parameter):
    """Data model for HIP ``HIP_TRANSPORT_MODE`` parameter."""

    #: Port.
    port: 'int'
    #: Mode IDs.
    mode_id: 'tuple[Transport, ...]'


@info_final
class HIPMACParameter(Parameter):
    """Data model for HIP ``HIP_MAC`` parameter."""

    #: HMAC value.
    hmac: 'bytes'


@info_final
class HIPMAC2Parameter(Parameter):
    """Data model for HIP ``HIP_MAC_2`` parameter."""

    #: HMAC value.
    hmac: 'bytes'


@info_final
class HIPSignature2Parameter(Parameter):
    """Data model for HIP ``HIP_SIGNATURE_2`` parameter."""

    #: Signature algorithm.
    algorithm: 'HIAlgorithm'
    #: Signature value.
    signature: 'bytes'


@info_final
class HIPSignatureParameter(Parameter):
    """Data model for HIP ``HIP_SIGNATURE`` parameter."""

    #: Signature algorithm.
    algorithm: 'HIAlgorithm'
    #: Signature value.
    signature: 'bytes'


@info_final
class EchoRequestUnsignedParameter(Parameter):
    """Data model for HIP ``ECHO_REQUEST_UNSIGNED`` parameter."""

    #: Opaque data.
    opaque: 'bytes'


@info_final
class EchoResponseUnsignedParameter(Parameter):
    """Data model for HIP ``ECHO_RESPONSE_UNSIGNED`` parameter."""

    #: Opaque data.
    opaque: 'bytes'


@info_final
class RelayFromParameter(Parameter):
    """Data model for HIP ``RELAY_FROM`` parameter."""

    #: Port.
    port: 'int'
    #: Protocol.
    protocol: 'TransType'
    #: Address.
    address: 'IPv6Address'


@info_final
class RelayToParameter(Parameter):
    """Data model for HIP ``RELAY_TO`` parameter."""

    #: Port.
    port: 'int'
    #: Protocol.
    protocol: 'TransType'
    #: Address.
    address: 'IPv6Address'


@info_final
class OverlayTTLParameter(Parameter):
    """Data model for HIP ``OVERLAY_TTL`` parameter."""

    #: TTL value.
    ttl: 'timedelta'


@info_final
class RouteViaParameter(Parameter):
    """Data model for HIP ``ROUTE_VIA`` parameter."""

    #: Flags.
    flags: 'Flags'
    #: HIT addresses.
    hit: 'tuple[IPv6Address, ...]'


@info_final
class FromParameter(Parameter):
    """Data model for HIP ``FROM`` parameter."""

    #: HIT address.
    address: 'IPv6Address'


@info_final
class RVSHMACParameter(Parameter):
    """Data model for HIP ``RVS_HMAC`` parameter."""

    #: HMAC value.
    hmac: 'bytes'


@info_final
class ViaRVSParameter(Parameter):
    """Data model for HIP ``VIA_RVS`` parameter."""

    #: Addresses.
    address: 'tuple[IPv6Address, ...]'


@info_final
class RelayHMACParameter(Parameter):
    """Data model for HIP ``RELAY_HMAC`` parameter."""

    #: HMAC value.
    hmac: 'bytes'
