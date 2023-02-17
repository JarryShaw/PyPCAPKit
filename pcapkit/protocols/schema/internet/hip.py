# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for Host Identity Protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.hip.parameter import Parameter as Enum_Parameter
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.misc import ListField, PayloadField
from pcapkit.corekit.fields.numbers import (EnumField, NumberField, UInt8Field, UInt16Field,
                                            UInt32Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema

__all__ = [
    'HIP',

    'LocatorData', 'Locator',

    'LocatorData', 'Locator',
    'HostIdentity',
    'Lifetime',
    'Flags',

    'UnassignedParameter', 'ESPInfoParameter', 'R1CounterParameter',
    'LocatorSetParameter', 'PuzzleParameter', 'SolutionParameter',
    'SEQParameter', 'ACKParameter', 'DHGroupListParameter',
    'DeffieHellmanParameter', 'HIPTransformParameter', 'HIPCipherParameter',
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
    from typing_extensions import Literal, TypedDict
    from ipaddress import IPv4Address

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
    value: 'IPv4Address | LocatorData' = BytesField(length=lambda pkt: pkt['len'] * 4)

    if TYPE_CHECKING:
        def __init__(self, traffic: 'int', type: 'int', len: 'int', flags: 'LocatorFlags',
                     lifetime: 'int', value: 'bytes | LocatorData') -> 'None': ...


class LocatorData(Schema):
    """Header schema for HIP locator data."""

    #: SPI.
    spi: 'int' = UInt32Field()
    #: Locator.
    ip: 'bytes' = BytesField(length=16)

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
