# -*- coding: utf-8 -*-
"""data model for HOPOPT protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

if TYPE_CHECKING:
    from datetime import timedelta
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional

    from pcapkit.const.ipv6.option import Option as RegType_Option
    from pcapkit.const.ipv6.qs_function import QSFunction
    from pcapkit.const.ipv6.router_alert import RouterAlert
    from pcapkit.const.ipv6.seed_id import SeedID
    from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
    from pcapkit.const.ipv6.tagger_id import TaggerID
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.corekit.multidict import OrderedMultiDict

__all__ = [
    'HOPOPT',

    'RPLFlags', 'MPLFlags', 'DFFFlags',

    'UnassignedOption', 'PadOption', 'TunnelEncapsulationLimitOption',
    'RouterAlertOption', 'CALIPSOOption', 'SMFIdentificationBasedDPDOption',
    'SMFHashBasedDPDOption', 'PDMOption', 'QuickStartOption',
    'RPLOption', 'MPLOption', 'ILNPOption',
    'LineIdentificationOption', 'JumboPayloadOption', 'HomeAddressOption',
    'IPDFFOption',
]


class Option(Info):
    """Data model for HOPOPT option data."""

    #: Option type.
    type: 'RegType_Option'
    #: Unknown option cation.
    action: 'int'
    #: Change flag.
    change: 'bool'
    #: Content length.
    length: 'int'


class HOPOPT(Info):
    """Data model for HOPOPT protocol."""

    #: Next header.
    next: 'TransType'
    #: Header extension length.
    length: 'int'
    #: HOPOPT options.
    options: 'OrderedMultiDict[RegType_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', options: 'OrderedMultiDict[RegType_Option, Option]') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class UnassignedOption(Option):
    """Data model for HOPOPT unassigned option."""

    #: Option data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class PadOption(Option):
    """Data model for HOPOPT padding options."""

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class TunnelEncapsulationLimitOption(Option):
    """Data model for HOPOPT tunnel encapsulation limit option."""

    #: Tunnel encapsulation limit.
    limit: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', limit: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class RouterAlertOption(Option):
    """Data model for HOPOPT router alter option."""

    #: Router alter value.
    value: 'RouterAlert'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', value: 'RouterAlert') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class CALIPSOOption(Option):
    """Data model for HOPOPT Common Architecture Label IPv6 Security Option (CALIPSO) option."""

    #: CALIPSO domain of interpretation.
    domain: 'int'
    #: Compartment length.
    cmpt_len: 'int'
    #: Sensitivity level.
    level: 'int'
    #: Checksum.
    checksum: 'bytes'

    if TYPE_CHECKING:
        #: Compartment bitmap.
        cmpt_bitmap: 'tuple[int, ...]'

        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', domain: 'int', cmpt_len: 'int', level: 'int', checksum: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class SMFDPDOption(Option):
    """Data model for HOPOPT Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) option."""

    #: DPD type.
    dpd_type: 'SMFDPDMode'
    #: TaggerID type.
    tid_type: 'TaggerID'


class SMFIdentificationBasedDPDOption(SMFDPDOption):
    """Data model for HOPOPT **I-DPD** (Identification-Based DPD) option."""

    #: TaggerID length.
    tid_len: 'int'
    #: TaggerID.
    tid: 'Optional[int | IPv4Address | IPv6Address]'
    #: Identifier.
    id: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', dpd_type: 'SMFDPDMode', tid_type: 'TaggerID', tid_len: 'int', tid: 'Optional[int | IPv4Address | IPv6Address]', id: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class SMFHashBasedDPDOption(SMFDPDOption):
    """Data model for HOPOPT **H-DPD** (Hash-Based DPD) option."""

    #: Hash assist value.
    hav: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', dpd_type: 'SMFDPDMode', tid_type: 'TaggerID', hav: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class PDMOption(Option):
    """Data model for HOPOPT Performance Diagnostic Metrics (PDM) option."""

    #: Scale delta time last received.
    scaledtlr: 'timedelta'
    #: Scale delta time last sent.
    scaledtls: 'timedelta'
    #: Packet sequence number this packet.
    psntp: 'int'
    #: Packet sequence number last received.
    psnlr: 'int'
    #: Delta time last received.
    deltatlr: 'timedelta'
    #: Delta time last sent.
    deltatls: 'timedelta'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', scaledtlr: 'timedelta', scaledtls: 'timedelta', psntp: 'int', psnlr: 'int', deltatlr: 'timedelta', deltatls: 'timedelta') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class QuickStartOption(Option):
    """Data model for HOPOPT Quick Start option."""

    #: QS function.
    func: 'QSFunction'
    #: Rate request/report.
    rate: 'int'
    #: TTL.
    ttl: 'Optional[timedelta]'
    #: Nounce.
    nounce: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', func: 'QSFunction', rate: 'int', ttl: 'Optional[timedelta]', nounce: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class RPLFlags(Info):
    """Data model for HOPOPT RPL option flags fields."""

    #: Down flag.
    down: 'bool'
    #: Rank error flag.
    rank_err: 'bool'
    #: Forwarding error flag.
    fwd_err: 'bool'

    if TYPE_CHECKING:
        def __init__(self, down: 'bool', rank_err: 'bool', fwd_err: 'bool') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class RPLOption(Option):
    """Data model for HOPOPT Routing Protocol for Low-Power and Lossy Networks (RPL) option."""

    #: Flags.
    flags: 'RPLFlags'
    #: RPL instance ID.
    id: 'int'
    #: Sender rank.
    rank:' int'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', flags: 'RPLFlags', id: 'int', rank: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class MPLFlags(Info):
    """Data model for HOPOPT MPL option flags fields."""

    #: Max flag.
    max: 'bool'
    #: Verification flag.
    verification: 'bool'

    if TYPE_CHECKING:
        def __init__(self, max: 'bool', verification: 'bool') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class MPLOption(Option):
    """Data model for HOPOPT Multicast Protocol for Low-Power and Lossy Networks (MPL) option."""

    #: Seed length.
    seed_type: 'SeedID'
    #: Flags.
    flags: 'MPLFlags'
    #: Sequence number.
    seq: 'int'
    #: Seed ID.
    seed_id: 'Optional[int]'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', seed_type: 'int', flags: 'MPLFlags', seq: 'int', seed_id: 'Optional[int]') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class ILNPOption(Option):
    """Data model for HOPOPT Identifier-Locator Network Protocol (ILNP) Nonce option."""

    #: Nonce value.
    nounce: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', nounce: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class LineIdentificationOption(Option):
    """Data model for HOPOPT Line-Identification option."""

    #: Line ID length.
    line_id_len: 'int'
    #: Line ID.
    line_id: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', line_id_len: 'int', line_id: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class JumboPayloadOption(Option):
    """Data model for Jumbo Payload option."""

    #: Jumbo payload length.
    payload_len: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', payload_len: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class HomeAddressOption(Option):
    """Data model for HOPOPT Home Address option."""

    #: Home address.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', address: 'IPv6Address') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class DFFFlags(Info):
    """Data model for HOPOPT ``IP_DFF`` option flags."""

    #: Duplicate flag.
    dup: 'bool'
    #: Return flag.
    ret: 'bool'

    if TYPE_CHECKING:
        def __init__(self, dup: 'bool', ret: 'bool') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class IPDFFOption(Option):
    """Data model for HOPOPT Depth-First Forwarding (``IP_DFF``) option."""

    #: Version.
    version: 'int'
    #:Flags.
    flags: 'DFFFlags'
    #: Sequence number.
    seq: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'RegType_Option', action: 'int', change: 'bool', length: 'int', version: 'int', flags: 'DFFFlags', seq: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long
