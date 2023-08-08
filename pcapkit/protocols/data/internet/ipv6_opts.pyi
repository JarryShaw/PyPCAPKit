from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address
from pcapkit.const.ipv6.option import Option as Enum_Option
from pcapkit.const.ipv6.option_action import OptionAction
from pcapkit.const.ipv6.qs_function import QSFunction
from pcapkit.const.ipv6.router_alert import RouterAlert
from pcapkit.const.ipv6.seed_id import SeedID
from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
from pcapkit.const.ipv6.tagger_id import TaggerID
from pcapkit.const.reg.transtype import TransType
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.data import Data
from typing import Optional

class Option(Data):
    type: Enum_Option
    action: OptionAction
    change: bool
    length: int

class IPv6_Opts(Data):
    next: TransType
    length: int
    options: OrderedMultiDict[Enum_Option, Option]
    def __init__(self, next: TransType, length: int, options: OrderedMultiDict[Enum_Option, Option]) -> None: ...

class UnassignedOption(Option):
    data: bytes
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, data: bytes) -> None: ...

class PadOption(Option):
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int) -> None: ...

class TunnelEncapsulationLimitOption(Option):
    limit: int
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, limit: int) -> None: ...

class RouterAlertOption(Option):
    value: RouterAlert
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, value: RouterAlert) -> None: ...

class CALIPSOOption(Option):
    domain: int
    cmpt_len: int
    level: int
    checksum: bytes
    cmpt_bitmap: bytes
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, domain: int, cmpt_len: int, level: int, checksum: bytes) -> None: ...

class SMFDPDOption(Option):
    dpd_type: SMFDPDMode

class SMFIdentificationBasedDPDOption(SMFDPDOption):
    tid_type: TaggerID
    tid_len: int
    tid: Optional[bytes | IPv4Address | IPv6Address]
    id: bytes
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, dpd_type: SMFDPDMode, tid_type: TaggerID, tid_len: int, tid: Optional[bytes | IPv4Address | IPv6Address], id: bytes) -> None: ...

class SMFHashBasedDPDOption(SMFDPDOption):
    hav: bytes
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, dpd_type: SMFDPDMode, hav: bytes) -> None: ...

class PDMOption(Option):
    scaledtlr: int
    scaledtls: int
    psntp: int
    psnlr: int
    deltatlr: int
    deltatls: int
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, scaledtlr: int, scaledtls: int, psntp: int, psnlr: int, deltatlr: int, deltatls: int) -> None: ...

class QuickStartOption(Option):
    func: QSFunction
    rate: int

class QuickStartRequestOption(QuickStartOption):
    ttl: timedelta
    nonce: int
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, func: QSFunction, rate: int, ttl: timedelta, nonce: int) -> None: ...

class QuickStartReportOption(QuickStartOption):
    nonce: int
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, func: QSFunction, rate: int, nonce: int) -> None: ...

class RPLFlags(Data):
    down: bool
    rank_err: bool
    fwd_err: bool
    def __init__(self, down: bool, rank_err: bool, fwd_err: bool) -> None: ...

class RPLOption(Option):
    flags: RPLFlags
    id: int
    rank: int
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, flags: RPLFlags, id: int, rank: int) -> None: ...

class MPLFlags(Data):
    max: bool
    drop: bool
    def __init__(self, max: bool, drop: bool) -> None: ...

class MPLOption(Option):
    seed_type: SeedID
    flags: MPLFlags
    seq: int
    seed_id: Optional[int]
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, seed_type: int, flags: MPLFlags, seq: int, seed_id: Optional[int]) -> None: ...

class ILNPOption(Option):
    nonce: int
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, nonce: int) -> None: ...

class LineIdentificationOption(Option):
    line_id_len: int
    line_id: bytes
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, line_id_len: int, line_id: bytes) -> None: ...

class JumboPayloadOption(Option):
    jumbo_len: int
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, jumbo_len: int) -> None: ...

class HomeAddressOption(Option):
    address: IPv6Address
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, address: IPv6Address) -> None: ...

class DFFFlags(Data):
    dup: bool
    ret: bool
    def __init__(self, dup: bool, ret: bool) -> None: ...

class IPDFFOption(Option):
    version: int
    flags: DFFFlags
    seq: int
    def __init__(self, type: Enum_Option, action: int, change: bool, length: int, version: int, flags: DFFFlags, seq: int) -> None: ...
