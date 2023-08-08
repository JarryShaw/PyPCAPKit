from datetime import timedelta
from ipaddress import IPv6Address
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
from pcapkit.protocols.data.data import Data
from typing import Optional

class Control(Data):
    anonymous: bool
    def __init__(self, anonymous: bool) -> None: ...

class Parameter(Data):
    type: Enum_Parameter
    critical: bool
    length: int

class HIP(Data):
    next: TransType
    length: int
    type: Packet
    version: int
    chksum: bytes
    control: Control
    shit: int
    rhit: int
    parameters: OrderedMultiDict[Enum_Parameter, Parameter]
    def __init__(self, next: TransType, length: int, type: Packet, version: int, chksum: bytes, control: Control, shit: int, rhit: int) -> None: ...

class UnassignedParameter(Parameter):
    contents: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, contents: bytes) -> None: ...

class ESPInfoParameter(Parameter):
    index: int
    old_spi: int
    new_spi: int
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, index: int, old_spi: int, new_spi: int) -> None: ...

class R1CounterParameter(Parameter):
    counter: int
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, counter: int) -> None: ...

class LocatorData(Data):
    spi: int
    ip: IPv6Address
    def __init__(self, spi: int, ip: IPv6Address) -> None: ...

class Locator(Data):
    traffic: int
    type: int
    length: int
    preferred: bool
    lifetime: timedelta
    locator: LocatorData | IPv6Address
    def __init__(self, traffic: int, type: int, length: int, preferred: bool, lifetime: timedelta, locator: LocatorData | IPv6Address) -> None: ...

class LocatorSetParameter(Parameter):
    locator_set: tuple[Locator, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, locator_set: tuple[Locator, ...]) -> None: ...

class PuzzleParameter(Parameter):
    index: int
    lifetime: timedelta
    opaque: bytes
    random: int
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, index: int, lifetime: timedelta, opaque: bytes, random: int) -> None: ...

class SolutionParameter(Parameter):
    index: int
    lifetime: timedelta
    opaque: bytes
    random: int
    solution: int
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, index: int, lifetime: timedelta, opaque: bytes, random: int, solution: int) -> None: ...

class SEQParameter(Parameter):
    id: int
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, id: int) -> None: ...

class ACKParameter(Parameter):
    update_id: tuple[int, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, update_id: tuple[int, ...]) -> None: ...

class DHGroupListParameter(Parameter):
    group_id: tuple[Group, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, group_id: tuple[Group, ...]) -> None: ...

class DiffieHellmanParameter(Parameter):
    group_id: Group
    pub_len: int
    pub_val: int
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, group_id: Group, pub_len: int, pub_val: int) -> None: ...

class HIPTransformParameter(Parameter):
    suite_id: tuple[Suite, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, suite_id: tuple[Suite, ...]) -> None: ...

class HIPCipherParameter(Parameter):
    cipher_id: tuple[Cipher, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, cipher_id: tuple[Cipher, ...]) -> None: ...

class NATTraversalModeParameter(Parameter):
    mode_id: tuple[NATTraversal, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, mode_id: tuple[NATTraversal, ...]) -> None: ...

class TransactionPacingParameter(Parameter):
    min_ta: int
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, min_ta: int) -> None: ...

class EncryptedParameter(Parameter):
    cipher: Cipher
    iv: Optional[bytes]
    data: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, cipher: Cipher, iv: Optional[bytes], data: bytes) -> None: ...

class HostIdentity(Data):
    curve: ECDSACurve | ECDSALowCurve | EdDSACurve
    pubkey: bytes
    def __init__(self, curve: ECDSACurve | ECDSALowCurve | EdDSACurve, pubkey: bytes) -> None: ...

class HostIDParameter(Parameter):
    hi_len: int
    di_type: DITypes
    di_len: int
    algorithm: HIAlgorithm
    hi: HostIdentity | bytes
    di: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, hi_len: int, di_type: DITypes, di_len: int, algorithm: HIAlgorithm, hi: HostIdentity | bytes, di: bytes) -> None: ...

class HITSuiteListParameter(Parameter):
    suite_id: tuple[HITSuite, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, suite_id: tuple[HITSuite, ...]) -> None: ...

class CertParameter(Parameter):
    cert_group: Group
    cert_count: int
    cert_id: int
    cert_type: Certificate
    cert: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, cert_group: Group, cert_count: int, cert_id: int, cert_type: Certificate, cert: bytes) -> None: ...

class NotificationParameter(Parameter):
    msg_type: NotifyMessage
    msg: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, msg_type: NotifyMessage, msg: bytes) -> None: ...

class EchoRequestSignedParameter(Parameter):
    opaque: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, opaque: bytes) -> None: ...

class Lifetime(Data):
    min: timedelta
    max: timedelta
    def __init__(self, min: timedelta, max: timedelta) -> None: ...

class RegInfoParameter(Parameter):
    lifetime: Lifetime
    reg_type: tuple[Registration, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, lifetime: Lifetime, reg_type: tuple[Registration, ...]) -> None: ...

class RegRequestParameter(Parameter):
    lifetime: timedelta
    reg_type: tuple[Registration, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, lifetime: timedelta, reg_type: tuple[Registration, ...]) -> None: ...

class RegResponseParameter(Parameter):
    lifetime: timedelta
    reg_type: tuple[Registration, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, lifetime: timedelta, reg_type: tuple[Registration, ...]) -> None: ...

class RegFailedParameter(Parameter):
    lifetime: timedelta
    reg_type: tuple[RegistrationFailure, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, lifetime: timedelta, reg_type: tuple[RegistrationFailure, ...]) -> None: ...

class RegFromParameter(Parameter):
    port: int
    protocol: TransType
    address: IPv6Address
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, port: int, protocol: TransType, address: IPv6Address) -> None: ...

class EchoResponseSignedParameter(Parameter):
    opaque: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, opaque: bytes) -> None: ...

class TransportFormatListParameter(Parameter):
    tf_type: tuple[Enum_Parameter, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, tf_type: tuple[Enum_Parameter, ...]) -> None: ...

class ESPTransformParameter(Parameter):
    suite_id: tuple[ESPTransformSuite, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, suite_id: tuple[ESPTransformSuite, ...]) -> None: ...

class SeqDataParameter(Parameter):
    seq: int
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, seq: int) -> None: ...

class AckDataParameter(Parameter):
    ack: tuple[int, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, ack: tuple[int, ...]) -> None: ...

class PayloadMICParameter(Parameter):
    next: TransType
    payload: bytes
    mic: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, next: TransType, payload: bytes, mic: bytes) -> None: ...

class TransactionIDParameter(Parameter):
    id: int
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, id: int) -> None: ...

class OverlayIDParameter(Parameter):
    id: int
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, id: int) -> None: ...

class Flags(Data):
    symmetric: bool
    must_follow: bool
    def __init__(self, symmetric: bool, must_follow: bool) -> None: ...

class RouteDstParameter(Parameter):
    flags: Flags
    hit: tuple[IPv6Address, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, flags: Flags, hit: tuple[IPv6Address, ...]) -> None: ...

class HIPTransportModeParameter(Parameter):
    port: int
    mode_id: tuple[Transport, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, port: int, mode_id: tuple[Transport, ...]) -> None: ...

class HIPMACParameter(Parameter):
    hmac: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, hmac: bytes) -> None: ...

class HIPMAC2Parameter(Parameter):
    hmac: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, hmac: bytes) -> None: ...

class HIPSignature2Parameter(Parameter):
    algorithm: HIAlgorithm
    signature: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, algorithm: HIAlgorithm, signature: bytes) -> None: ...

class HIPSignatureParameter(Parameter):
    algorithm: HIAlgorithm
    signature: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, algorithm: HIAlgorithm, signature: bytes) -> None: ...

class EchoRequestUnsignedParameter(Parameter):
    opaque: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, opaque: bytes) -> None: ...

class EchoResponseUnsignedParameter(Parameter):
    opaque: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, opaque: bytes) -> None: ...

class RelayFromParameter(Parameter):
    port: int
    protocol: TransType
    address: IPv6Address
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, port: int, protocol: TransType, address: IPv6Address) -> None: ...

class RelayToParameter(Parameter):
    port: int
    protocol: TransType
    address: IPv6Address
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, port: int, protocol: TransType, address: IPv6Address) -> None: ...

class OverlayTTLParameter(Parameter):
    ttl: timedelta
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, ttl: timedelta) -> None: ...

class RouteViaParameter(Parameter):
    flags: Flags
    hit: tuple[IPv6Address, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, flags: Flags, hit: tuple[IPv6Address, ...]) -> None: ...

class FromParameter(Parameter):
    address: IPv6Address
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, address: IPv6Address) -> None: ...

class RVSHMACParameter(Parameter):
    hmac: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, hmac: bytes) -> None: ...

class ViaRVSParameter(Parameter):
    address: tuple[IPv6Address, ...]
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, address: tuple[IPv6Address, ...]) -> None: ...

class RelayHMACParameter(Parameter):
    hmac: bytes
    def __init__(self, type: Enum_Parameter, critical: bool, length: int, hmac: bytes) -> None: ...
