# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for Host Identity Protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.ipaddress import IPv6Field
from pcapkit.const.hip.certificate import Certificate as Enum_Certificate
from pcapkit.const.hip.cipher import Cipher as Enum_Cipher
from pcapkit.const.hip.di import DITypes as Enum_DITypes
from pcapkit.const.hip.ecdsa_curve import ECDSACurve as Enum_ECDSACurve
from pcapkit.const.hip.ecdsa_low_curve import ECDSALowCurve as Enum_ECDSALowCurve
from pcapkit.const.hip.eddsa_curve import EdDSACurve as Enum_EdDSACurve
from pcapkit.const.hip.esp_transform_suite import ESPTransformSuite as Enum_ESPTransformSuite
from pcapkit.const.hip.group import Group as Enum_Group
from pcapkit.const.hip.hi_algorithm import HIAlgorithm as Enum_HIAlgorithm
from pcapkit.const.hip.hit_suite import HITSuite as Enum_HITSuite
from pcapkit.const.hip.nat_traversal import NATTraversal as Enum_NATTraversal
from pcapkit.const.hip.notify_message import NotifyMessage as Enum_NotifyMessage
from pcapkit.const.hip.parameter import Parameter as Enum_Parameter
from pcapkit.const.hip.registration import Registration as Enum_Registration
from pcapkit.const.hip.registration_failure import RegistrationFailure as Enum_RegistrationFailure
from pcapkit.const.hip.suite import Suite as Enum_Suite
from pcapkit.const.hip.transport import Transport as Enum_Transport
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.misc import ConditionalField, ListField, PayloadField
from pcapkit.corekit.fields.numbers import (EnumField, NumberField, UInt8Field, UInt16Field,
                                            UInt32Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema

__all__ = [
    'HIP',

    'LocatorData', 'Locator',

    'LocatorData', 'Locator',
    'ECDSACurveHostIdentity', 'ECDSALowCurveHostIdentity', 'EdDSACurveHostIdentity',

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

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import Optional

    from typing_extensions import Literal, TypedDict

    from pcapkit.protocols.protocol import Protocol

    class PacketType(TypedDict):
        """Packet type."""

        #: Reversed bit.
        bit_0: Literal[0]
        #: Packet type.
        type: int

    class VersionType(TypedDict):
        """Version type."""

        #: Version.
        version: int
        #: Reversed bit.
        bit_1: Literal[1]

    class ControlsType(TypedDict):
        """Controls type."""

        #: Anonymous.
        anonymous: bool

    class LocatorFlags(TypedDict):
        """Locator flags."""

        #: Preferred flag.
        preferred: bool

    class DIData(TypedDict):
        """DI type data."""

        #: DI type.
        type: Enum_DITypes
        #: DI length.
        len: int

    class RouteFlags(TypedDict):
        """Route destination flags."""

        #: Symmetric flag.
        symmetric: int
        #: Must-follow flag.
        must_follow: int


class HIP(Schema):
    """Header schema for HIP packet."""

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Header length.
    len: 'int' = UInt8Field()
    #: Packet type.
    pkt: 'PacketType' = BitField(
        length=1,
        namespace={
            'bit_0': (0, 1),
            'type': (1, 7),
        },
    )
    #: HIP version.
    ver: 'VersionType' = BitField(
        length=1,
        namespace={
            'version': (0, 4),
            'bit_1': (7, 1),
        },
    )
    #: Checksum.
    checksum: 'bytes' = BytesField(length=2)
    #: HIP controls.
    control: 'ControlsType' = BitField(
        length=2,
        namespace={
            'anonymous': (15, 1),
        },
    )
    #: Sender's host identity tag.
    shit: 'int' = NumberField(length=16, signed=False)
    #: Receiver's host identity tag.
    rhit: 'int' = NumberField(length=16, signed=False)
    #: HIP parameters.
    param: 'list[Parameter]' = ListField(length=lambda pkt: (pkt['len'] - 4) * 8)
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType', len: 'int', pkt: 'PacketType',
                     ver: 'VersionType', checksum: 'bytes', control: 'ControlsType',
                     shit: 'int', rhit: 'int', param: 'bytes | list[bytes | Parameter]',
                     payload: 'bytes | Protocol | Schema') -> 'None': ...


class Parameter(Schema):
    """Base schema for HIP parameters."""

    #: Parameter type.
    type: 'Enum_Parameter' = EnumField(length=2, namespace=Enum_Parameter)
    #: Parameter length.
    len: 'int' = UInt16Field()


class UnassignedParameter(Parameter):
    """Header schema for HIP unsigned parameters."""

    #: Parameter value.
    value: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', value: 'bytes') -> 'None': ...


class ESPInfoParameter(Parameter):
    """Header schema for HIP ``ESP_INFO`` parameters."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Key management index.
    index: 'int' = UInt16Field()
    #: Old SPI.
    old_spi: 'int' = UInt32Field()
    #: New SPI.
    new_spi: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', index: 'int',
                     old_spi: 'int', new_spi: 'int') -> 'None': ...


class R1CounterParameter(Parameter):
    """Header schema for HIP ``R1_COUNTER`` parameters."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=4)
    #: R1 counter.
    counter: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', counter: 'int') -> 'None': ...


class LocatorSetParameter(Parameter):
    """Header schema for HIP ``LOCATOR_SET`` parameters."""

    #: List of locators.
    locators: 'list[Locator]' = ListField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', locators: 'list[Locator]') -> 'None': ...


class Locator(Schema):
    """Header schema for HIP locators."""

    #: Traffic type.
    traffic: 'int' = UInt8Field()
    #: Locator type.
    type: 'int' = UInt8Field()
    #: Locator length.
    len: 'int' = UInt8Field()
    #: Reserved and flags.
    flags: 'LocatorFlags' = BitField(
        length=1,
        namespace={
            'preferred': (7, 1),
        },
    )
    lifetime: 'int' = UInt32Field()
    #: Locator value.
    value: 'IPv6Address | LocatorData' = BytesField(length=lambda pkt: pkt['len'] * 4)

    if TYPE_CHECKING:
        def __init__(self, traffic: 'int', type: 'int', len: 'int', flags: 'LocatorFlags',
                     lifetime: 'int', value: 'bytes | LocatorData') -> 'None': ...


class LocatorData(Schema):
    """Header schema for HIP locator data."""

    #: SPI.
    spi: 'int' = UInt32Field()
    #: Locator.
    ip: 'IPv6Address' = IPv6Field()

    if TYPE_CHECKING:
        def __init__(self, spi: 'int', ip: 'IPv6Address | int | bytes | str') -> 'None': ...


class PuzzleParameter(Parameter):
    """Header schema for HIP ``PUZZLE`` parameters."""

    #: Numeric index.
    index: 'int' = UInt8Field()
    #: Lifetime.
    lifetime: 'int' = UInt8Field()
    #: Opaque data.
    opaque: 'bytes' = BytesField(length=2)
    #: Random data.
    random: 'int' = NumberField(length=lambda pkt: pkt['len'] - 4, signed=False)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', index: 'int', lifetime: 'int',
                     opaque: 'bytes', random: 'int') -> 'None': ...


class SolutionParameter(Parameter):
    """Header schema for HIP ``SOLUTION`` parameters."""

    #: Numeric index.
    index: 'int' = UInt8Field()
    #: Lifetime.
    lifetime: 'int' = UInt8Field()
    #: Opaque data.
    opaque: 'bytes' = BytesField(length=2)
    #: Random data.
    random: 'int' = NumberField(length=lambda pkt: (pkt['len'] - 4) // 2, signed=False)
    #: Solution.
    solution: 'int' = NumberField(length=lambda pkt: (pkt['len'] - 4) // 2, signed=False)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', index: 'int', lifetime: 'int',
                     opaque: 'bytes', random: 'int', solution: 'int') -> 'None': ...


class SEQParameter(Parameter):
    """Header schema for HIP ``SEQ`` parameters."""

    #: Update ID.
    update_id: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', update_id: 'int') -> 'None': ...


class ACKParameter(Parameter):
    """Header schema for HIP ``ACK`` parameters."""

    #: Update ID.
    update_id: 'list[int]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=UInt32Field(),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', update_id: 'bytes | list[int]') -> 'None': ...


class DHGroupListParameter(Parameter):
    """Header schema for HIP ``DH_GROUP_LIST`` parameters."""

    #: List of DH groups.
    groups: 'list[Enum_Group]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=EnumField(length=1, namespace=Enum_Group),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', groups: 'list[Enum_Group]') -> 'None': ...


class DiffieHellmanParameter(Parameter):
    """Header schema for HIP ``DIFFIE_HELLMAN`` parameters."""

    #: Diffie-Hellman group.
    group: 'Enum_Group' = EnumField(length=1, namespace=Enum_Group)
    #: Public value length.
    pub_len: 'int' = UInt16Field()
    #: Diffie-Hellman value.
    pub_val: 'int' = NumberField(length=lambda pkt: pkt['pub_len'], signed=False)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', group: 'Enum_Group', pub_len: 'int',
                     pub_val: 'int') -> 'None': ...


class HIPTransformParameter(Parameter):
    """Header schema for HIP ``TRANSFORM`` parameters."""

    #: Suite IDs.
    suites: 'list[Enum_Suite]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=EnumField(length=2, namespace=Enum_Suite),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', suites: 'list[Enum_Suite]') -> 'None': ...


class HIPCipherParameter(Parameter):
    """Header schema for HIP ``CIPHER`` parameters."""

    #: Cipher IDs.
    ciphers: 'list[Enum_Cipher]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=EnumField(length=2, namespace=Enum_Cipher),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', ciphers: 'list[Enum_Cipher]') -> 'None': ...


class NATTraversalModeParameter(Parameter):
    """Header schema for HIP ``NAT_TRAVERSAL_MODE`` parameters."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: NAT traversal modes.
    modes: 'list[Enum_NATTraversal]' = ListField(
        length=lambda pkt: pkt['len'] - 2,
        item_type=EnumField(length=1, namespace=Enum_NATTraversal),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', modes: 'list[Enum_NATTraversal]') -> 'None': ...


class TransactionPacingParameter(Parameter):
    """Header schema for HIP ``TRANSACTION_PACING`` parameters."""

    #: Transaction pacing.
    min_ta: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', min_ta: 'int') -> 'None': ...


class EncryptedParameter(Parameter):
    """Header schema for HIP ``ENCRYPTED`` parameters."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=4)
    #: Initialization vector.
    iv: 'bytes' = ConditionalField(
        BytesField(length=16),
        lambda pkt: pkt['__cipher__'] in (Enum_Cipher.AES_128_CBC, Enum_Cipher.AES_256_CBC),
    )
    #: Data.
    data: 'bytes' = BytesField(
        length=lambda pkt: pkt['len'] - (16 if pkt['iv'] else 0),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        #: Cipher ID.
        cipher: 'Enum_Cipher'

        def __init__(self, type: 'Enum_Parameter', len: 'int', cipher: 'Enum_Cipher',
                     iv: 'Optional[bytes]', data: 'bytes') -> 'None': ...


class HostIDParameter(Parameter):
    """Header schema for HIP ``HOST_ID`` parameters."""

    #: Host ID length.
    hi_len: 'int' = UInt16Field()
    #: Domain ID type and length.
    di_data: 'DIData' = BitField(
        length=4,
        namespace={
            'type': (0, 4),
            'len': (4, 12),
        },
    )
    #: Algorithm type.
    algorithm: 'Enum_HIAlgorithm' = EnumField(length=2, namespace=Enum_HIAlgorithm)
    #: Host ID.
    hi: 'bytes | ECDSACurveHostIdentity | ECDSALowCurveHostIdentity | EdDSACurveHostIdentity' = BytesField(length=lambda pkt: pkt['hi_len'])
    #: Domain ID.
    di: 'bytes' = BytesField(length=lambda pkt: pkt['di_data']['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', hi_len: 'int', di_data: 'DIData',
                     algorithm: 'Enum_HIAlgorithm', hi: 'bytes | ECDSACurveHostIdentity | ECDSALowCurveHostIdentity | EdDSACurveHostIdentity',
                     di: 'bytes') -> 'None': ...


class ECDSACurveHostIdentity(Schema):
    """Host identity schema with ECDSA curve."""

    #: Algorithm curve type.
    curve: 'Enum_ECDSACurve' = EnumField(length=2, namespace=Enum_ECDSACurve)
    #: Public key.
    pub_key: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'] - 2)

    if TYPE_CHECKING:
        def __init__(self, curve: 'Enum_ECDSACurve', pub_key: 'bytes') -> 'None': ...


class ECDSALowCurveHostIdentity(Schema):
    """Host identity schema with ECDSA_LOW curve."""

    #: Algorithm curve type.
    curve: 'Enum_ECDSALowCurve' = EnumField(length=2, namespace=Enum_ECDSALowCurve)
    #: Public key.
    pub_key: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'] - 2)

    if TYPE_CHECKING:
        def __init__(self, curve: 'Enum_ECDSALowCurve', pub_key: 'bytes') -> 'None': ...


class EdDSACurveHostIdentity(Schema):
    """Host identity schema with EdDSA curve."""

    #: Algorithm curve type.
    curve: 'Enum_EdDSACurve' = EnumField(length=2, namespace=Enum_EdDSACurve)
    #: Public key.
    pub_key: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'] - 2)

    if TYPE_CHECKING:
        def __init__(self, curve: 'Enum_EdDSACurve', pub_key: 'bytes') -> 'None': ...


class HITSuiteListParameter(Parameter):
    """Header schema for HIP ``HIT_SUITE_LIST`` parameters."""

    #: HIT suite IDs.
    suites: 'list[Enum_HITSuite]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=EnumField(length=1, namespace=Enum_HITSuite),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', suites: 'list[Enum_HITSuite]') -> 'None': ...


class CertParameter(Parameter):
    """Header schema for HIP ``CERT`` parameters."""

    #: Certificate group.
    cert_group: 'Enum_Group' = EnumField(length=1, namespace=Enum_Group)
    #: Certificate count.
    cert_count: 'int' = UInt8Field()
    #: Certificate ID.
    cert_id: 'int' = UInt8Field()
    #: Certificate type.
    cert_type: 'Enum_Certificate' = EnumField(length=1, namespace=Enum_Certificate)
    #: Certificate data.
    cert: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - 4)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', cert_group: 'Enum_Group', cert_count: 'int',
                     cert_id: 'int', cert_type: 'Enum_Certificate', cert: 'bytes') -> 'None': ...


class NotificationParameter(Parameter):
    """Header schema for HIP ``NOTIFICATION`` parameters."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Notify message type.
    msg_type: 'Enum_NotifyMessage' = EnumField(length=2, namespace=Enum_NotifyMessage)
    #: Notification data.
    msg: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - 4)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', msg_type: 'Enum_NotifyMessage', msg: 'bytes') -> 'None': ...


class EchoRequestSignedParameter(Parameter):
    """Header schema for HIP ``ECHO_REQUEST_SIGNED`` parameters."""

    #: Opaque data.
    opaque: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', opaque: 'bytes') -> 'None': ...


class RegInfoParameter(Parameter):
    """Header schema for HIP ``REG_INFO`` parameters."""

    #: Minimum lifetime.
    min_lifetime: 'int' = UInt8Field()
    #: Maximum lifetime.
    max_lifetime: 'int' = UInt8Field()
    #: Registration types.
    reg_info: 'list[Enum_Registration]' = ListField(
        length=lambda pkt: pkt['len'] - 2,
        item_type=EnumField(length=1, namespace=Enum_Registration),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', min_lifetime: 'int', max_lifetime: 'int',
                     reg_info: 'list[Enum_Registration]') -> 'None': ...


class RegRequestParameter(Parameter):
    """Header schema for HIP ``REG_REQUEST`` parameters."""

    #: Lifetime.
    lifetime: 'int' = UInt8Field()
    #: Registration types.
    reg_request: 'list[Enum_Registration]' = ListField(
        length=lambda pkt: pkt['len'] - 1,
        item_type=EnumField(length=1, namespace=Enum_Registration),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', lifetime: 'int', reg_request: 'list[Enum_Registration]') -> 'None': ...


class RegResponseParameter(Parameter):
    """Header schema for HIP ``REG_RESPONSE`` parameters."""

    #: Lifetime.
    lifetime: 'int' = UInt8Field()
    #: Registration types.
    reg_response: 'list[Enum_Registration]' = ListField(
        length=lambda pkt: pkt['len'] - 1,
        item_type=EnumField(length=1, namespace=Enum_Registration),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', lifetime: 'int', reg_response: 'list[Enum_Registration]') -> 'None': ...


class RegFailedParameter(Parameter):
    """Header schema for HIP ``REG_FAILED`` parameters."""

    #: Lifetime.
    lifetime: 'int' = UInt8Field()
    #: Registration types.
    reg_failed: 'list[Enum_RegistrationFailure]' = ListField(
        length=lambda pkt: pkt['len'] - 1,
        item_type=EnumField(length=1, namespace=Enum_RegistrationFailure),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', lifetime: 'int', reg_failed: 'list[Enum_RegistrationFailure]') -> 'None': ...


class RegFromParameter(Parameter):
    """Header schema for HIP ``REG_FROM`` parameters."""

    #: Port.
    port: 'int' = UInt16Field()
    #: Protocol.
    protocol: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Address.
    address: 'IPv6Address' = IPv6Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', port: 'int', protocol: 'Enum_TransType', address: 'IPv6Address | bytes | int | str') -> 'None': ...


class EchoResponseSignedParameter(Parameter):
    """Header schema for HIP ``ECHO_RESPONSE_SIGNED`` parameters."""

    #: Opaque data.
    opaque: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', opaque: 'bytes') -> 'None': ...


class TransportFormatListParameter(Parameter):
    """Header schema for HIP ``TRANSPORT_FORMAT_LIST`` parameters."""

    #: Transport formats.
    formats: 'list[Enum_Parameter]' = ListField(
        length=lambda pkt: pkt['len'] - 2,
        item_type=EnumField(length=1, namespace=Enum_Parameter),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', formats: 'list[Enum_Parameter]') -> 'None': ...


class ESPTransformParameter(Parameter):
    """Header schema for HIP ``ESP_TRANSFORM`` parameters."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Suite IDs.
    suites: 'list[Enum_ESPTransformSuite]' = ListField(
        length=lambda pkt: pkt['len'] - 2,
        item_type=EnumField(length=1, namespace=Enum_ESPTransformSuite),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', suites: 'list[Enum_ESPTransformSuite]') -> 'None': ...


class SeqDataParameter(Parameter):
    """Header schema for HIP ``SEQ_DATA`` parameters."""

    #: Sequence number.
    seq: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', seq: 'int') -> 'None': ...


class AckDataParameter(Parameter):
    """Header schema for HIP ``ACK_DATA`` parameters."""

    #: Acked sequence number.
    ack: 'list[int]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=UInt32Field(),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', ack: 'list[int]') -> 'None': ...


class PayloadMICParameter(Parameter):
    """Header schema for HIP ``PAYLOAD_MIC`` parameters."""

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Reversed.
    reserved: 'bytes' = PaddingField(length=3)
    #: Payload data.
    payload: 'bytes' = BytesField(length=4)
    #: MIC value.
    mic: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - 8)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', next: 'Enum_TransType', payload: 'bytes', mic: 'bytes') -> 'None': ...


class TransactionIDParameter(Parameter):
    """Header schema for HIP ``TRANSACTION_ID`` parameters."""

    #: Transaction ID.
    id: 'int' = NumberField(length=lambda pkt: pkt['len'], signed=False)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', id: 'int') -> 'None': ...


class OverlayIDParameter(Parameter):
    """Header schema for HIP ``OVERLAY_ID`` parameters."""

    #: Overlay ID.
    id: 'int' = NumberField(length=lambda pkt: pkt['len'], signed=False)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', id: 'int') -> 'None': ...


class RouteDstParameter(Parameter):
    """Header schema for HIP ``ROUTE_DST`` parameters."""

    #: Flags.
    flags: 'RouteFlags' = BitField(length=2, namespace={
            'symmetric': (0, 1),
            'must_follow': (1, 1),
    })
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: HIT addresses.
    hit: 'list[IPv6Address]' = ListField(
        length=lambda pkt: pkt['len'] - 4,
        item_type=IPv6Field(),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', flags: 'RouteFlags', hit: 'list[str | int | bytes | IPv6Address]') -> 'None': ...


class HIPTransportModeParameter(Parameter):
    """Header schema for HIP ``HIP_TRANSPORT_MODE`` parameters."""

    #: Port.
    port: 'int' = UInt16Field()
    #: Mode IDs.
    mode: 'list[Enum_Transport]' = ListField(
        length=lambda pkt: pkt['len'] - 2,
        item_type=EnumField(length=2, namespace=Enum_Transport),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', port: 'int', mode: 'list[Enum_Transport]') -> 'None': ...


class HIPMACParameter(Parameter):
    """Header schema for HIP ``HIP_MAC`` parameters."""

    #: HMAC value.
    hmac: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', hmac: 'bytes') -> 'None': ...


class HIPMAC2Parameter(Parameter):
    """Header schema for HIP ``HIP_MAC_2`` parameters."""

    #: HMAC value.
    hmac: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', hmac: 'bytes') -> 'None': ...


class HIPSignature2Parameter(Parameter):
    """Header schema for HIP ``HIP_SIGNATURE_2`` parameters."""

    #: Signature algorithm.
    algorithm: 'Enum_HIAlgorithm' = EnumField(length=2, namespace=Enum_HIAlgorithm)
    #: Signature value.
    signature: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - 2)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', algorithm: 'Enum_HIAlgorithm', signature: 'bytes') -> 'None': ...


class HIPSignatureParameter(Parameter):
    """Header schema for HIP ``HIP_SIGNATURE`` parameters."""

    #: Signature algorithm.
    algorithm: 'Enum_HIAlgorithm' = EnumField(length=2, namespace=Enum_HIAlgorithm)
    #: Signature value.
    signature: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - 2)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', algorithm: 'Enum_HIAlgorithm', signature: 'bytes') -> 'None': ...


class EchoRequestUnsignedParameter(Parameter):
    """Header schema for HIP ``ECHO_REQUEST_UNSIGNED`` parameters."""

    #: Opaque data.
    opaque: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', opaque: 'bytes') -> 'None': ...


class EchoResponseUnsignedParameter(Parameter):
    """Header schema for HIP ``ECHO_RESPONSE_UNSIGNED`` parameters."""

    #: Opaque data.
    opaque: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', opaque: 'bytes') -> 'None': ...


class RelayFromParameter(Parameter):
    """Header schema for HIP ``RELAY_FROM`` parameters."""

    #: Port.
    port: 'int' = UInt16Field()
    #: Protocol.
    protocol: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Address.
    address: 'IPv6Address' = IPv6Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', port: 'int', protocol: 'Enum_TransType', address: 'str | bytes | int | IPv6Address') -> 'None': ...


class RelayToParameter(Parameter):
    """Header schema for HIP ``RELAY_TO`` parameters."""

    #: Port.
    port: 'int' = UInt16Field()
    #: Protocol.
    protocol: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Address.
    address: 'IPv6Address' = IPv6Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', port: 'int', protocol: 'Enum_TransType', address: 'str | bytes | int | IPv6Address') -> 'None': ...


class OverlayTTLParameter(Parameter):
    """Header schema for HIP ``OVERLAY_TTL`` parameters."""

    #: TTL value.
    ttl: 'int' = UInt16Field()
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', ttl: 'int') -> 'None': ...


class RouteViaParameter(Parameter):
    """Header schema for HIP ``ROUTE_VIA`` parameters."""

    #: Flags.
    flags: 'RouteFlags' = BitField(length=2, namespace={
        'symmetric': (0, 1),
        'must_follow': (1, 1),
    })
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: HIT addresses.
    hit: 'list[IPv6Address]' = ListField(
        length=lambda pkt: pkt['len'] - 4,
        item_type=IPv6Field(),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', flags: 'RouteFlags', hit: 'list[str | bytes | int | IPv6Address]') -> 'None': ...


class FromParameter(Parameter):
    """Header schema for HIP ``FROM`` parameters."""

    #: Address.
    address: 'IPv6Address' = IPv6Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', address: 'str | bytes | int | IPv6Address') -> 'None': ...


class RVSHMACParameter(Parameter):
    """Header schema for HIP ``RVS_HMAC`` parameters."""

    #: HMAC value.
    hmac: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', hmac: 'bytes') -> 'None': ...


class ViaRVSParameter(Parameter):
    """Header schema for HIP ``VIA_RVS`` parameters."""

    #: Address.
    address: 'list[IPv6Address]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=IPv6Field(),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', address: 'list[str | bytes | int | IPv6Address]') -> 'None': ...


class RelayHMACParameter(Parameter):
    """Header schema for HIP ``RELAY_HMAC`` parameters."""

    #: HMAC value.
    hmac: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', hmac: 'bytes') -> 'None': ...
