# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for hop-by-hop options"""

from typing import TYPE_CHECKING

from pcapkit.protocols.schema.schema import Schema
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.ipaddress import IPv6Field
from pcapkit.corekit.fields.misc import ConditionalField, ListField, PayloadField
from pcapkit.corekit.fields.numbers import (EnumField, NumberField, UInt8Field, UInt16Field,
                                            UInt32Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.const.ipv6.option import Option as Enum_Option
from pcapkit.const.ipv6.router_alert import RouterAlert as Enum_RouterAlert

__all__ = [
    'HOPOPT',

    'RPLFlags', 'MPLFlags', 'DFFFlags',

    'SMFDPDOption', 'QuickStartOption',
    'UnassignedOption', 'PadOption', 'TunnelEncapsulationLimitOption',
    'RouterAlertOption', 'CALIPSOOption', 'SMFIdentificationBasedDPDOption',
    'SMFHashBasedDPDOption', 'PDMOption', 'QuickStartRequestOption',
    'QuickStartReportOption', 'RPLOption', 'MPLOption', 'ILNPOption',
    'LineIdentificationOption', 'JumboPayloadOption', 'HomeAddressOption',
    'IPDFFOption',
]

if TYPE_CHECKING:
    from typing import Optional
    from ipaddress import IPv4Address, IPv6Address

    from typing_extensions import TypedDict

    from pcapkit.protocols.protocol import Protocol

    class TaggerIDInfo(TypedDict):
        """TaggerID information."""

        #: SMF mode.
        mode: int
        #: TaggerID type.
        type: int
        #: TaggerID length.
        len: int

    class QuickStartFlags(TypedDict):
        """Quick-Start flags."""

        #: QS function.
        func: int
        #: Rate request/report.
        rate: int


class HOPOPT(Schema):
    """Header schema for HOPOPT packet."""

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Header length.
    len: 'int' = UInt8Field()
    #: Options.
    options: 'list[Option]' = ListField(length=lambda pkt: pkt['len'] * 8 + 6)
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType', len: 'int',
                     options: 'bytes | list[bytes | Option]',
                     payload: 'bytes | Protocol | Schema') -> 'None': ...


class Option(Schema):
    """Header schema for HOPOPT options."""

    #: Option type.
    type: 'Enum_Option' = EnumField(length=1, namespace=Enum_Option)
    #: Option length (conditional in case of ``Pad1`` option).
    len: 'int' = ConditionalField(
        UInt8Field(default=0),
        lambda pkt: pkt['type'] != Enum_Option.Pad1,
    )


class UnassignedOption(Option):
    """Header schema for HOPOPT unassigned options."""

    #: Option data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', data: 'bytes') -> 'None': ...


class PadOption(Option):
    """Header schema for HOPOPT padding options."""

    #: Padding.
    pad: 'bytes' = PaddingField(length=lambda pkt: pkt['len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int') -> 'None': ...


class TunnelEncapsulationLimitOption(Option):
    """Header schema for HOPOPT tunnel encapsulation limit options."""

    #: Tunnel encapsulation limit.
    limit: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', limit: 'int') -> 'None': ...


class RouterAlertOption(Option):
    """Header schema for HOPOPT router alert options."""

    #: Router alert.
    alert: 'Enum_RouterAlert' = EnumField(length=2, namespace=Enum_RouterAlert)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', alert: 'Enum_RouterAlert') -> 'None': ...


class CALIPSOOption(Option):
    """Header schema for HOPOPT common architecture label IPv6 security options."""

    #: CALIPSO domain of interpretation.
    domain: 'int' = UInt32Field()
    #: Compartment length.
    cmpt_len: 'int' = UInt8Field()
    #: Sens level.
    level: 'int' = UInt8Field()
    #: Checksum (CRC-16).
    checksum: 'bytes' = BytesField(length=2)
    #: Compartment bitmap.
    bitmap: 'bytes' = ConditionalField(
        BytesField(length=lambda pkt: pkt['cmpt_len'] * 4),
        lambda pkt: pkt['cmpt_len'] > 0,
    )
    #: Padding.
    pad: 'bytes' = PaddingField(length=lambda pkt: pkt['len'] - 8 - pkt['cmpt_len'] * 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', domain: 'int', cmpt_len: 'int',
                     level: 'int', checksum: 'bytes', bitmap: 'Optional[bytes]') -> 'None': ...


class SMFDPDOption(Option):
    """Header schema for HOPOPT simplified multicast forwarding duplicate packet
    detection (``SMF_DPD``) options."""


class SMFIdentificationBasedDPDOption(SMFDPDOption):
    """Header schema for HOPOPT SMF identification-based DPD options."""

    #: TaggerID information.
    info: 'TaggerIDInfo' = BitField(length=1, namespace={
        'mode': (0, 1),
        'type': (1, 3),
        'len': (4, 4),
    })
    #: TaggerID.
    tid: 'bytes | IPv4Address | IPv6Address' = ConditionalField(
        BytesField(length=lambda pkt: pkt['info']['len'] + 1),
        lambda pkt: pkt['info']['type'] != 0,
    )
    #: Identifier.
    id: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - (
        1 if pkt['info']['type'] == 0 else (pkt['info']['len'] + 2)
    ))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', info: 'TaggerIDInfo',
                     tid: 'Optional[bytes]', id: 'bytes') -> 'None': ...


class SMFHashBasedDPDOption(SMFDPDOption):
    """Header schema for HOPOPT SMF hash-based DPD options."""

    #: Hash assist value (HAV).
    hav: 'bytes' = BytesField(length=lambda pkt: pkt['len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', hav: 'bytes') -> 'None': ...


class PDMOption(Option):
    """Header schema for HOPOPT performance and diagnostic metrics (PDM) options."""

    #: Scale delta time last received (DTLR).
    scaledtlr: 'int' = UInt8Field()
    #: Scale delta time last sent (DTLS).
    scaledtls: 'int' = UInt8Field()
    #: Packet sequence number (PSN) this packet.
    psntp: 'int' = UInt16Field()
    #: Packet sequence number (PSN) last received.
    psnlr: 'int' = UInt16Field()
    #: Delta time last received (DTLR).
    deltatlr: 'int' = UInt16Field()
    #: Delta time last sent (DTLS).
    deltatls: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', scaledtlr: 'int', scaledtls: 'int',
                     psntp: 'int', psnlr: 'int', deltatlr: 'int', deltatls: 'int') -> 'None': ...


class QuickStartOption(Option):
    """Header schema for HOPOPT quick start options."""

    #: Flags.
    flags: 'QuickStartFlags' = BitField(length=1, namespace={
        'func': (0, 4),
        'rate': (4, 4),
    })


class QuickStartRequestOption(QuickStartOption):
    """Header schema for HOPOPT quick start request options."""

    #: QS time-to-live (TTL).
    ttl: 'int' = UInt8Field()
    #: QS nounce.
    nounce: 'bytes' = BytesField(length=4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'QuickStartFlags',
                     ttl: 'int', nounce: 'bytes') -> 'None': ...


class QuickStartReportOption(QuickStartOption):
    """Header schema for HOPOPT quick start report of approved rate options."""

    #: QS nounce.
    nounce: 'bytes' = BytesField(length=4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'QuickStartFlags',
                     nounce: 'bytes') -> 'None': ...
