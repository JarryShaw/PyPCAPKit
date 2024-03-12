# -*- coding: utf-8 -*-
"""data model for HIP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

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

    if TYPE_CHECKING:
        def __init__(self, anonymous: 'bool') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,multiple-statements


class Parameter(Data):
    """Data model for HIP parameter data."""

    #: Parameter type.
    type: 'Enum_Parameter'
    #: Critical flag.
    critical: 'bool'
    #: Content length.
    length: 'int'


@info_final
class HIP(Protocol):
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

    if TYPE_CHECKING:
        #: HIP parameters.
        parameters: 'OrderedMultiDict[Enum_Parameter, Parameter]'

        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', version: 'int', chksum: 'bytes', control: 'Control', shit: 'int', rhit: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class UnassignedParameter(Parameter):
    """Data model for unassigned parameter."""

    #: Content.
    contents: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', contents: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class ESPInfoParameter(Parameter):
    """Data model for HIP ``ESP_INFO`` parameter."""

    #: KEYMAT index.
    index: 'int'
    #: Old SDI.
    old_spi: 'int'
    #: New SDI.
    new_spi: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', index: 'int', old_spi: 'int', new_spi: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class R1CounterParameter(Parameter):
    """Data model for HIP ``R1_COUNTER`` parameter."""

    #: R1 counter.
    counter: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', counter: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class LocatorData(Data):
    """Data model for HIP locator data."""

    #: SPI.
    spi: 'int'
    #: IP address.
    ip: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, spi: 'int', ip: 'IPv6Address') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,multiple-statements


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

    if TYPE_CHECKING:
        def __init__(self, traffic: 'int', type: 'int', length: 'int', preferred: 'bool', lifetime: 'timedelta', locator: 'LocatorData | IPv6Address') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,multiple-statements,redefined-builtin,line-too-long


@info_final
class LocatorSetParameter(Parameter):
    """Data model for HIP ``LOCATOR_SET`` parameter."""

    #: Locator set.
    locator_set: 'tuple[Locator, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', locator_set: 'tuple[Locator, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


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

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', index: 'int', lifetime: 'timedelta', opaque: 'bytes', random: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


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

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', index: 'int', lifetime: 'timedelta', opaque: 'bytes', random: 'int', solution: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class SEQParameter(Parameter):
    """Data model for HIP ``SEQ`` parameter."""

    #: Unique ID.
    id: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', id: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class ACKParameter(Parameter):
    """Data model for HIP ``ACK`` parameter."""

    #: Peer update IDs.
    update_id: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', update_id: 'tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class DHGroupListParameter(Parameter):
    """Data model for HIP ``DH_GROUP_LIST`` parameter."""

    #: DH group list.
    group_id: 'tuple[Group, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', group_id: 'tuple[Group, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class DiffieHellmanParameter(Parameter):
    """Data model for HIP ``DIFFIE_HELLMAN`` parameter."""

    #: Group ID.
    group_id: 'Group'
    #: Public value length.
    pub_len: 'int'
    #: Public value.
    pub_val: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', group_id: 'Group', pub_len: 'int', pub_val: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class HIPTransformParameter(Parameter):
    """Data model for HIP ``HIP_TRANSFORM`` parameter."""

    #: Suite IDs.
    suite_id: 'tuple[Suite, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', suite_id: 'tuple[Suite, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class HIPCipherParameter(Parameter):
    """Data model for HIP ``HIP_CIPHER`` parameter."""

    #: Cipher IDs.
    cipher_id: 'tuple[Cipher, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', cipher_id: 'tuple[Cipher, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class NATTraversalModeParameter(Parameter):
    """Data model for HIP ``NAT_TRAVERSAL_MODE`` parameter."""

    #: Mode IDs
    mode_id: 'tuple[NATTraversal, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', mode_id: 'tuple[NATTraversal, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class TransactionPacingParameter(Parameter):
    """Data model for HIP ``TRANSACTION_PACING`` parameter."""

    #: Min TA.
    min_ta: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', min_ta: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class EncryptedParameter(Parameter):
    """Data model for HIP ``ENCRYPTED`` parameter."""

    #: Cipher ID.
    cipher: 'Cipher'
    #: Initialization vector.
    iv: 'Optional[bytes]'
    #: Encrypted data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int',
                     cipher: 'Cipher', iv: 'Optional[bytes]', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class HostIdentity(Data):
    """Data model for host identity."""

    #: Curve type.
    curve: 'ECDSACurve | ECDSALowCurve | EdDSACurve'
    #: Public key.
    pubkey: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, curve: 'ECDSACurve | ECDSALowCurve | EdDSACurve',
                     pubkey: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


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

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', hi_len: 'int', di_type: 'DITypes', di_len: 'int', algorithm: 'HIAlgorithm', hi: 'HostIdentity | bytes', di: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class HITSuiteListParameter(Parameter):
    """Data model for HIP ``HIST_SUITE_LIST`` parameter."""

    #: Suite IDs.
    suite_id: 'tuple[HITSuite, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', suite_id: 'tuple[HITSuite, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


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

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', cert_group: 'Group', cert_count: 'int', cert_id: 'int', cert_type: 'Certificate', cert: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class NotificationParameter(Parameter):
    """Data model for HIP ``NOTIFICATION`` parameter."""

    #: Notify message type.
    msg_type: 'NotifyMessage'
    #: Notification data.
    msg: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', msg_type: 'NotifyMessage', msg: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class EchoRequestSignedParameter(Parameter):
    """Data model for HIP ``ECHO_REQUEST_SIGNED`` parameter."""

    #: Opaque data.
    opaque: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', opaque: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class Lifetime(Data):
    """Data model for registration lifetime."""

    #: Minimum lifetime.
    min: 'timedelta'
    #: Maximum lifetime.
    max: 'timedelta'

    if TYPE_CHECKING:
        def __init__(self, min: 'timedelta', max: 'timedelta') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class RegInfoParameter(Parameter):
    """Data model for HIP ``REG_INFO`` parameter."""

    #: Registration lifetime.
    lifetime: 'Lifetime'
    #: Registration type.
    reg_type: 'tuple[Registration, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', lifetime: 'Lifetime', reg_type: 'tuple[Registration, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class RegRequestParameter(Parameter):
    """Data model for HIP ``REG_REQUEST`` parameter."""

    #: Registration lifetime.
    lifetime: 'timedelta'
    #: Registration type.
    reg_type: 'tuple[Registration, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', lifetime: 'timedelta', reg_type: 'tuple[Registration, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class RegResponseParameter(Parameter):
    """Data model for HIP ``REG_RESPONSE`` parameter."""

    #: Registration lifetime.
    lifetime: 'timedelta'
    #: Registration type.
    reg_type: 'tuple[Registration, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', lifetime: 'timedelta', reg_type: 'tuple[Registration, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class RegFailedParameter(Parameter):
    """Data model for HIP ``REG_FAILED`` parameter."""

    #: Registration lifetime.
    lifetime: 'timedelta'
    #: Registration failure type.
    reg_type: 'tuple[RegistrationFailure, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', lifetime: 'timedelta', reg_type: 'tuple[RegistrationFailure, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class RegFromParameter(Parameter):
    """Data model for HIP ``REG_FROM`` parameter."""

    #: Port.
    port: 'int'
    #: Protocol.
    protocol: 'TransType'
    #: Address.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', port: 'int', protocol: 'TransType', address: 'IPv6Address') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class EchoResponseSignedParameter(Parameter):
    """Data model for HIP ``ECHO_RESPONSE_SIGNED`` parameter."""

    #: Opaque data.
    opaque: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', opaque: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class TransportFormatListParameter(Parameter):
    """Data model for HIP ``TRANSPORT_FORMAT_LIST`` parameter."""

    #: Transport format list.
    tf_type: 'tuple[Enum_Parameter, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', tf_type: 'tuple[Enum_Parameter, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class ESPTransformParameter(Parameter):
    """Data model for HIP ``ESP_TRANSFORM`` parameter."""

    #: ESP transform.
    suite_id: 'tuple[ESPTransformSuite, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', suite_id: 'tuple[ESPTransformSuite, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class SeqDataParameter(Parameter):
    """Data model for HIP ``SEQ_DATA`` parameter."""

    #: Sequence number.
    seq: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', seq: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class AckDataParameter(Parameter):
    """Data model for HIP ``ACK_DATA`` parameter."""

    #: Acknowledged sequence number.
    ack: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', ack: 'tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class PayloadMICParameter(Parameter):
    """Data model for HIP ``PAYLOAD_MIC`` parameter."""

    #: Next header
    next: 'TransType'
    #: Payload data.
    payload: 'bytes'
    #: MIC value.
    mic: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', next: 'TransType', payload: 'bytes', mic: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class TransactionIDParameter(Parameter):
    """Data model for HIP ``TRANSACTION_ID`` parameter."""

    #: Identifier.
    id: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', id: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class OverlayIDParameter(Parameter):
    """Data mode HIP ``OVERLAY_ID`` parameter."""

    #: Identifier.
    id: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', id: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class Flags(Data):
    """Data model for flags in HIP ``HIP_PARAMETER_FLAGS`` parameter."""

    #: Symmetric flag.
    symmetric: 'bool'
    #: Must follow flag.
    must_follow: 'bool'

    if TYPE_CHECKING:
        def __init__(self, symmetric: 'bool', must_follow: 'bool') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class RouteDstParameter(Parameter):
    """Data model for HIP ``ROUTE_DST`` parameter."""

    #: Flags.
    flags: 'Flags'
    #: Destination address.
    hit: 'tuple[IPv6Address, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', flags: 'Flags', hit: 'tuple[IPv6Address, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class HIPTransportModeParameter(Parameter):
    """Data model for HIP ``HIP_TRANSPORT_MODE`` parameter."""

    #: Port.
    port: 'int'
    #: Mode IDs.
    mode_id: 'tuple[Transport, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', port: 'int', mode_id: 'tuple[Transport, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class HIPMACParameter(Parameter):
    """Data model for HIP ``HIP_MAC`` parameter."""

    #: HMAC value.
    hmac: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', hmac: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class HIPMAC2Parameter(Parameter):
    """Data model for HIP ``HIP_MAC_2`` parameter."""

    #: HMAC value.
    hmac: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', hmac: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class HIPSignature2Parameter(Parameter):
    """Data model for HIP ``HIP_SIGNATURE_2`` parameter."""

    #: Signature algorithm.
    algorithm: 'HIAlgorithm'
    #: Signature value.
    signature: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', algorithm: 'HIAlgorithm', signature: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class HIPSignatureParameter(Parameter):
    """Data model for HIP ``HIP_SIGNATURE`` parameter."""

    #: Signature algorithm.
    algorithm: 'HIAlgorithm'
    #: Signature value.
    signature: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', algorithm: 'HIAlgorithm', signature: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class EchoRequestUnsignedParameter(Parameter):
    """Data model for HIP ``ECHO_REQUEST_UNSIGNED`` parameter."""

    #: Opaque data.
    opaque: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', opaque: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class EchoResponseUnsignedParameter(Parameter):
    """Data model for HIP ``ECHO_RESPONSE_UNSIGNED`` parameter."""

    #: Opaque data.
    opaque: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', opaque: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class RelayFromParameter(Parameter):
    """Data model for HIP ``RELAY_FROM`` parameter."""

    #: Port.
    port: 'int'
    #: Protocol.
    protocol: 'TransType'
    #: Address.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', port: 'int', protocol: 'TransType', address: 'IPv6Address') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class RelayToParameter(Parameter):
    """Data model for HIP ``RELAY_TO`` parameter."""

    #: Port.
    port: 'int'
    #: Protocol.
    protocol: 'TransType'
    #: Address.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', port: 'int', protocol: 'TransType', address: 'IPv6Address') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class OverlayTTLParameter(Parameter):
    """Data model for HIP ``OVERLAY_TTL`` parameter."""

    #: TTL value.
    ttl: 'timedelta'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', ttl: 'timedelta') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class RouteViaParameter(Parameter):
    """Data model for HIP ``ROUTE_VIA`` parameter."""

    #: Flags.
    flags: 'Flags'
    #: HIT addresses.
    hit: 'tuple[IPv6Address, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', flags: 'Flags', hit: 'tuple[IPv6Address, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class FromParameter(Parameter):
    """Data model for HIP ``FROM`` parameter."""

    #: HIT address.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', address: 'IPv6Address') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class RVSHMACParameter(Parameter):
    """Data model for HIP ``RVS_HMAC`` parameter."""

    #: HMAC value.
    hmac: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', hmac: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class ViaRVSParameter(Parameter):
    """Data model for HIP ``VIA_RVS`` parameter."""

    #: Addresses.
    address: 'tuple[IPv6Address, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', address: 'tuple[IPv6Address, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long


@info_final
class RelayHMACParameter(Parameter):
    """Data model for HIP ``RELAY_HMAC`` parameter."""

    #: HMAC value.
    hmac: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', critical: 'bool', length: 'int', hmac: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,redefined-builtin,super-init-not-called,line-too-long
