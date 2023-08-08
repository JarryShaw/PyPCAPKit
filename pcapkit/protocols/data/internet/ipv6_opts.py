# -*- coding: utf-8 -*-
"""data model for IPv6 Destination Options protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.utilities.compat import NotRequired

if TYPE_CHECKING:
    from datetime import timedelta
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional

    from pcapkit.const.ipv6.option import Option as Enum_Option
    from pcapkit.const.ipv6.option_action import OptionAction
    from pcapkit.const.ipv6.qs_function import QSFunction
    from pcapkit.const.ipv6.router_alert import RouterAlert
    from pcapkit.const.ipv6.seed_id import SeedID
    from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
    from pcapkit.const.ipv6.tagger_id import TaggerID
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.corekit.multidict import OrderedMultiDict

__all__ = [
    'IPv6_Opts',

    'RPLFlags', 'MPLFlags', 'DFFFlags',

    'SMFDPDOption', 'QuickStartOption',
    'UnassignedOption', 'PadOption', 'TunnelEncapsulationLimitOption',
    'RouterAlertOption', 'CALIPSOOption', 'SMFIdentificationBasedDPDOption',
    'SMFHashBasedDPDOption', 'PDMOption', 'QuickStartRequestOption',
    'QuickStartReportOption', 'RPLOption', 'MPLOption', 'ILNPOption',
    'LineIdentificationOption', 'JumboPayloadOption', 'HomeAddressOption',
    'IPDFFOption',
]


class Option(Data):
    """Data model for IPv6-Opts option data."""

    #: Option type.
    type: 'Enum_Option'
    #: Unknown option cation.
    action: 'OptionAction'
    #: Change flag.
    change: 'bool'
    #: Content length.
    length: 'int'


@info_final
class IPv6_Opts(Data):
    """Data model for IPv6-Opts protocol."""

    #: Next header.
    next: 'TransType'
    #: Header extension length.
    length: 'int'
    #: IPv6-Opts options.
    options: 'OrderedMultiDict[Enum_Option, Option]'


@info_final
class UnassignedOption(Option):
    """Data model for IPv6-Opts unassigned option."""

    #: Option data.
    data: 'bytes'


@info_final
class PadOption(Option):
    """Data model for IPv6-Opts padding options."""


@info_final
class TunnelEncapsulationLimitOption(Option):
    """Data model for IPv6-Opts tunnel encapsulation limit option."""

    #: Tunnel encapsulation limit.
    limit: 'int'


@info_final
class RouterAlertOption(Option):
    """Data model for IPv6-Opts router alter option."""

    #: Router alter value.
    value: 'RouterAlert'


@info_final
class CALIPSOOption(Option):
    """Data model for IPv6-Opts Common Architecture Label IPv6 Security Option (CALIPSO) option."""

    #: CALIPSO domain of interpretation.
    domain: 'int'
    #: Compartment length.
    cmpt_len: 'int'
    #: Sensitivity level.
    level: 'int'
    #: Checksum.
    checksum: 'bytes'

    #: Compartment bitmap.
    cmpt_bitmap: 'bytes' = NotRequired  # type: ignore[assignment]


class SMFDPDOption(Option):
    """Data model for IPv6-Opts Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) option."""

    #: DPD type.
    dpd_type: 'SMFDPDMode'


@info_final
class SMFIdentificationBasedDPDOption(SMFDPDOption):
    """Data model for IPv6-Opts **I-DPD** (Identification-Based DPD) option."""

    #: TaggerID type.
    tid_type: 'TaggerID'
    #: TaggerID length.
    tid_len: 'int'
    #: TaggerID.
    tid: 'Optional[bytes | IPv4Address | IPv6Address]'
    #: Identifier.
    id: 'bytes'


@info_final
class SMFHashBasedDPDOption(SMFDPDOption):
    """Data model for IPv6-Opts **H-DPD** (Hash-Based DPD) option."""

    #: Hash assist value.
    hav: 'bytes'


@info_final
class PDMOption(Option):
    """Data model for IPv6-Opts Performance Diagnostic Metrics (PDM) option."""

    #: Scale delta time last received.
    scaledtlr: 'int'
    #: Scale delta time last sent.
    scaledtls: 'int'
    #: Packet sequence number this packet.
    psntp: 'int'
    #: Packet sequence number last received.
    psnlr: 'int'
    #: Delta time last received (in attoseconds).
    deltatlr: 'int'
    #: Delta time last sent (in attoseconds).
    deltatls: 'int'


class QuickStartOption(Option):
    """Data model for IPv6-Opts Quick Start option."""

    #: QS function.
    func: 'QSFunction'
    #: Rate request/report.
    rate: 'int'


@info_final
class QuickStartRequestOption(QuickStartOption):
    """Data model for IPv6-Opts Quick Start request option."""

    #: TTL.
    ttl: 'timedelta'
    #: Nonce.
    nonce: 'int'


@info_final
class QuickStartReportOption(QuickStartOption):
    """Data model for IPv6-Opts Quick Start report of approved rate option."""

    #: Nonce.
    nonce: 'int'


@info_final
class RPLFlags(Data):
    """Data model for IPv6-Opts RPL option flags fields."""

    #: Down flag.
    down: 'bool'
    #: Rank error flag.
    rank_err: 'bool'
    #: Forwarding error flag.
    fwd_err: 'bool'


@info_final
class RPLOption(Option):
    """Data model for IPv6-Opts Routing Protocol for Low-Power and Lossy Networks (RPL) option."""

    #: Flags.
    flags: 'RPLFlags'
    #: RPL instance ID.
    id: 'int'
    #: Sender rank.
    rank: ' int'


@info_final
class MPLFlags(Data):
    """Data model for IPv6-Opts MPL option flags fields."""

    #: Max flag.
    max: 'bool'
    #: Non-conformation flag.
    drop: 'bool'


@info_final
class MPLOption(Option):
    """Data model for IPv6-Opts Multicast Protocol for Low-Power and Lossy Networks (MPL) option."""

    #: Seed length.
    seed_type: 'SeedID'
    #: Flags.
    flags: 'MPLFlags'
    #: Sequence number.
    seq: 'int'
    #: Seed ID.
    seed_id: 'Optional[int]'


@info_final
class ILNPOption(Option):
    """Data model for IPv6-Opts Identifier-Locator Network Protocol (ILNP) Nonce option."""

    #: Nonce value.
    nonce: 'int'


@info_final
class LineIdentificationOption(Option):
    """Data model for IPv6-Opts Line-Identification option."""

    #: Line ID length.
    line_id_len: 'int'
    #: Line ID.
    line_id: 'bytes'


@info_final
class JumboPayloadOption(Option):
    """Data model for Jumbo Payload option."""

    #: Jumbo payload length.
    jumbo_len: 'int'


@info_final
class HomeAddressOption(Option):
    """Data model for IPv6-Opts Home Address option."""

    #: Home address.
    address: 'IPv6Address'


@info_final
class DFFFlags(Data):
    """Data model for IPv6-Opts ``IP_DFF`` option flags."""

    #: Duplicate flag.
    dup: 'bool'
    #: Return flag.
    ret: 'bool'


@info_final
class IPDFFOption(Option):
    """Data model for IPv6-Opts Depth-First Forwarding (``IP_DFF``) option."""

    #: Version.
    version: 'int'
    # :Flags.
    flags: 'DFFFlags'
    #: Sequence number.
    seq: 'int'
