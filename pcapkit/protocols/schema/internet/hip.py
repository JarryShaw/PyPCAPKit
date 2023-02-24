# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for Host Identity Protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.hip.parameter import Parameter as Enum_Parameter
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.misc import ListField, PayloadField, ConditionalField
from pcapkit.corekit.fields.numbers import (EnumField, NumberField, UInt8Field, UInt16Field,
                                            UInt32Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema
from pcapkit.const.hip.group import Group as Enum_Group
from pcapkit.const.hip.suite import Suite as Enum_Suite
from pcapkit.const.hip.cipher import Cipher as Enum_Cipher
from pcapkit.const.hip.nat_traversal import NATTraversal as Enum_NATTraversal
from pcapkit.const.hip.di import DITypes as Enum_DITypes
from pcapkit.const.hip.hi_algorithm import HIAlgorithm as Enum_HIAlgorithm
from pcapkit.const.hip.ecdsa_curve import ECDSACurve as Enum_ECDSACurve
from pcapkit.const.hip.ecdsa_low_curve import ECDSALowCurve as Enum_ECDSALowCurve

__all__ = [
    'HIP',

    'LocatorData', 'Locator',

    'LocatorData', 'Locator',
    'ECDSACurveHostIdentity', 'ECDSALowCurveHostIdentity',
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

if TYPE_CHECKING:
    from typing import Optional
    from typing_extensions import Literal, TypedDict
    from ipaddress import IPv6Address

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
    """Header schema for HIP ESP information parameters."""

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
    """Header schema for HIP R1 counter parameters."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=4)
    #: R1 counter.
    counter: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', counter: 'int') -> 'None': ...


class LocatorSetParameter(Parameter):
    """Header schema for HIP locator set parameters."""

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
    ip: 'bytes' = BytesField(length=4)

    if TYPE_CHECKING:
        def __init__(self, spi: 'int', ip: 'bytes') -> 'None': ...


class PuzzleParameter(Parameter):
    """Header schema for HIP puzzle parameters."""

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
    """Header schema for HIP solution parameters."""

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
    """Header schema for HIP SEQ parameters."""

    #: Update ID.
    update_id: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', update_id: 'int') -> 'None': ...


class ACKParameter(Parameter):
    """Header schema for HIP ACK parameters."""

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
    """Header schema for HIP DH group list parameters."""

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
    """Header schema for HIP Diffie-Hellman parameters."""

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
    """Header schema for HIP transform parameters."""

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
    """Header schema for HIP cipher parameters."""

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
    """Header schema for HIP NAT traversal mode parameters."""

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
    """Header schema for HIP transaction pacing parameters."""

    #: Transaction pacing.
    min_ta: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', min_ta: 'int') -> 'None': ...


class EncryptedParameter(Parameter):
    """Header schema for HIP encrypted parameters."""

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
    """Header schema for HIP host ID parameters."""

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
    hi: 'bytes | ECDSACurveHostIdentity | ECDSALowCurveHostIdentity' = BytesField(length=lambda pkt: pkt['hi_len'])
    #: Domain ID.
    di: 'bytes' = BytesField(length=lambda pkt: pkt['di_data']['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (8 - (pkt['len'] % 8)) % 8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', hi_len: 'int', di_data: 'DIData',
                     algorithm: 'Enum_HIAlgorithm', hi: 'bytes | ECDSACurveHostIdentity | ECDSALowCurveHostIdentity',
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
    """Host identity schema with ECDSA low curve."""

    #: Algorithm curve type.
    curve: 'Enum_ECDSALowCurve' = EnumField(length=2, namespace=Enum_ECDSALowCurve)
    #: Public key.
    pub_key: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'] - 2)

    if TYPE_CHECKING:
        def __init__(self, curve: 'Enum_ECDSALowCurve', pub_key: 'bytes') -> 'None': ...
