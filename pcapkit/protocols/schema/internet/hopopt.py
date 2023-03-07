# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for hop-by-hop options"""

from typing import TYPE_CHECKING

from pcapkit.const.ipv6.option import Option as Enum_Option
from pcapkit.const.ipv6.router_alert import RouterAlert as Enum_RouterAlert
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.ipaddress import IPv6Field
from pcapkit.corekit.fields.misc import ConditionalField, ListField, PayloadField
from pcapkit.corekit.fields.numbers import (EnumField, NumberField, UInt8Field, UInt16Field,
                                            UInt32Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import FieldValueError

__all__ = [
    'HOPOPT',

    'SMFDPDOption', 'QuickStartOption',
    'UnassignedOption', 'PadOption', 'TunnelEncapsulationLimitOption',
    'RouterAlertOption', 'CALIPSOOption', 'SMFIdentificationBasedDPDOption',
    'SMFHashBasedDPDOption', 'PDMOption', 'QuickStartRequestOption',
    'QuickStartReportOption', 'RPLOption', 'MPLOption', 'ILNPOption',
    'LineIdentificationOption', 'JumboPayloadOption', 'HomeAddressOption',
    'IPDFFOption',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Optional

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

    class RPLFlags(TypedDict):
        """RPL flags."""

        #: Down flag.
        down: int
        #: Rank error flag.
        rank_err: int
        #: Forwarding error flag.
        fwd_err: int

    class MPLFlags(TypedDict):
        """MPL flags."""

        #: Seed-ID type. Identifies the length of the
        #: Seed-ID.
        type: int
        #: Max flag. ``1`` indicates that the value in the
        #: sequence field is known to be the largest sequence
        #: number that was received from the MPL Seed.
        max: int
        #: Verification flag. ``0`` indicates that the MPL Option
        #: conforms to this specification.
        drop: int

    class DFFFlags(TypedDict):
        """``IP_DFF`` flags."""

        #: Version.
        ver: int
        #: Duplicate flag.
        dup: int
        #: Retune flag.
        ret: int


def mpl_opt_seed_id_len(pkt: 'dict[str, Any]') -> 'int':
    """Return MPL Seed-ID length.

    Args:
        pkt: MPL option unpacked schema.

    Returns:
        MPL Seed-ID length.

    """
    s_type = pkt['flags']['type']
    if s_type == 0:
        return 0
    if s_type == 1:
        return 2
    if s_type == 2:
        return 8
    if s_type == 3:
        return 16
    raise FieldValueError(f'HOPOPT: invalid MPL Seed-ID type: {s_type}')


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
    #: QS nonce.
    nonce: 'bytes' = BytesField(length=4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'QuickStartFlags',
                     ttl: 'int', nonce: 'bytes') -> 'None': ...


class QuickStartReportOption(QuickStartOption):
    """Header schema for HOPOPT quick start report of approved rate options."""

    #: QS nonce.
    nonce: 'bytes' = BytesField(length=4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'QuickStartFlags',
                     nonce: 'bytes') -> 'None': ...


class RPLOption(Option):
    """Header schema for HOPOPT routing protocol for low-power and lossy networks (RPL) options."""

    #: Flags.
    flags: 'RPLFlags' = BitField(length=1, namespace={
        'down': (0, 1),
        'rank_err': (1, 1),
        'fwd_err': (2, 1),
    })
    #: RPL instance ID.
    id: 'int' = UInt8Field()
    #: Sender rank.
    rank: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'RPLFlags', id: 'int',
                     rank: 'int') -> 'None': ...


class MPLOption(Option):
    """Header schema for HOPOPT multicast protocol for low-power and lossy networks (MPL) options."""

    #: Flags.
    flags: 'MPLFlags' = BitField(length=1, namespace={
        'type': (0, 2),
        'max': (2, 1),
        'drop': (3, 1),
    })
    #: MPL sequence number.
    seq: 'int' = UInt8Field()
    #: MPL Seed-ID.
    seed: 'int' = ConditionalField(
        NumberField(length=mpl_opt_seed_id_len, signed=False),
        lambda pkt: pkt['flags']['type'] != 0,
    )
    #: Reserved data (padding).
    pad: 'bytes' = PaddingField(length=lambda pkt: pkt['len'] - 2 - (
        0 if pkt['flags']['type'] == 0 else mpl_opt_seed_id_len(pkt)
    ))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'MPLFlags', seq: 'int',
                     seed: 'Optional[int]') -> 'None': ...


class ILNPOption(Option):
    """Header schema for HOPOPT identifier-locator network protocol (ILNP) options."""

    #: Nonce value.
    nonce: 'bytes' = BytesField(length=lambda pkt: pkt['len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', nonce: 'bytes') -> 'None': ...


class LineIdentificationOption(Option):
    """Header schema for HOPOPT line-identification options."""

    #: Line ID length.
    id_len: 'int' = UInt8Field()
    #: Line ID.
    id: 'bytes' = BytesField(length=lambda pkt: pkt['id_len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', id_len: 'int', id: 'bytes') -> 'None': ...


class JumboPayloadOption(Option):
    """Header schema for HOPOPT jumbo payload options."""

    #: Jumbo payload length.
    jumbo_len: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', jumbo_len: 'int') -> 'None': ...


class HomeAddressOption(Option):
    """Header schema for HOPOPT home address options."""

    #: Home address.
    addr: 'IPv6Address' = IPv6Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', addr: 'IPv6Address | int | str | bytes') -> 'None': ...


class IPDFFOption(Option):
    """Header schema for HOPOPT depth-first forwarding (``IP_DFF``) options."""

    #: Flags.
    flags: 'DFFFlags' = BitField(length=1, namespace={
        'ver': (0, 2),
        'dup': (2, 1),
        'ret': (3, 1),
    })
    #: Sequence number.
    seq: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'DFFFlags', seq: 'int') -> 'None': ...
