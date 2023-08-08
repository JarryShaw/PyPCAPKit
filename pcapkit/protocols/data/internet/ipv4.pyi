from datetime import timedelta
from ipaddress import IPv4Address
from pcapkit.const.ipv4.classification_level import ClassificationLevel
from pcapkit.const.ipv4.option_number import OptionNumber
from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
from pcapkit.const.ipv4.qs_function import QSFunction
from pcapkit.const.ipv4.router_alert import RouterAlert
from pcapkit.const.ipv4.tos_ecn import ToSECN
from pcapkit.const.ipv4.tos_pre import ToSPrecedence
from pcapkit.const.ipv4.tos_rel import ToSReliability
from pcapkit.const.ipv4.tos_thr import ToSThroughput
from pcapkit.const.ipv4.ts_flag import TSFlag
from pcapkit.const.reg.transtype import TransType
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.data import Data
from typing import Any, Optional
from typing_extensions import Literal

class ToSField(Data):
    pre: ToSPrecedence
    thr: ToSThroughput
    rel: ToSReliability
    ecn: ToSECN
    def __new__(cls, *args: Any, **kwargs: Any) -> ToSField: ...

class Flags(Data):
    df: bool
    mf: bool
    def __init__(self, df: bool, mf: bool) -> None: ...

class IPv4(Data):
    version: Literal[4]
    hdr_len: int
    tos: ToSField
    len: int
    id: int
    flags: Flags
    offset: int
    ttl: timedelta
    protocol: TransType
    checksum: bytes
    src: IPv4Address
    dst: IPv4Address
    options: OrderedMultiDict[OptionNumber, Option]
    def __init__(self, version: Literal[4], hdr_len: int, tos: ToSField, len: int, id: int, flags: Flags, offset: int, ttl: timedelta, protocol: TransType, checksum: bytes, src: IPv4Address, dst: IPv4Address) -> None: ...

class OptionType(Data):
    change: bool
    number: int
    def __new__(cls, *args: Any, **kwargs: Any) -> OptionType: ...

class Option(Data):
    code: OptionNumber
    length: int
    type: OptionType

class UnassignedOption(Option):
    data: bytes
    def __init__(self, code: OptionNumber, length: int, type: OptionType, data: bytes) -> None: ...

class EOOLOption(Option):
    def __init__(self, code: OptionNumber, length: int, type: OptionType) -> None: ...

class NOPOption(Option):
    def __init__(self, code: OptionNumber, length: int, type: OptionType) -> None: ...

class SECOption(Option):
    level: ClassificationLevel
    flags: tuple[ProtectionAuthority, ...]
    def __init__(self, code: OptionNumber, length: int, type: OptionType, level: ClassificationLevel, flags: tuple[ProtectionAuthority, ...]) -> None: ...

class LSROption(Option):
    pointer: int
    route: tuple[IPv4Address, ...]
    def __init__(self, code: OptionNumber, length: int, type: OptionType, pointer: int, route: tuple[IPv4Address, ...]) -> None: ...

class TSOption(Option):
    pointer: int
    overflow: int
    flag: TSFlag
    timestamp: tuple[timedelta | int, ...] | OrderedMultiDict[IPv4Address, timedelta | int]
    def __init__(self, code: OptionNumber, length: int, type: OptionType, pointer: int, overflow: int, flag: TSFlag, timestamp: tuple[timedelta | int, ...] | OrderedMultiDict[IPv4Address, timedelta | int]) -> None: ...

class ESECOption(Option):
    format: int
    info: bytes
    def __init__(self, code: OptionNumber, length: int, type: OptionType, format: int, info: bytes) -> None: ...

class RROption(Option):
    pointer: int
    route: Optional[tuple[IPv4Address, ...]]
    def __init__(self, code: OptionNumber, length: int, type: OptionType, pointer: int, route: Optional[tuple[IPv4Address, ...]]) -> None: ...

class SIDOption(Option):
    sid: int
    def __init__(self, code: OptionNumber, length: int, type: OptionType, sid: int) -> None: ...

class SSROption(Option):
    pointer: int
    route: Optional[tuple[IPv4Address, ...]]
    def __init__(self, code: OptionNumber, length: int, type: OptionType, pointer: int, route: Optional[tuple[IPv4Address, ...]]) -> None: ...

class MTUPOption(Option):
    mtu: int
    def __init__(self, code: OptionNumber, length: int, type: OptionType, mtu: int) -> None: ...

class MTUROption(Option):
    mtu: int
    def __init__(self, code: OptionNumber, length: int, type: OptionType, mtu: int) -> None: ...

class TROption(Option):
    id: int
    outbound: int
    originator: IPv4Address
    def __new__(cls, *args: Any, **kwargs: Any) -> TROption: ...

class RTRALTOption(Option):
    alert: RouterAlert
    def __init__(self, code: OptionNumber, length: int, type: OptionType, alert: RouterAlert) -> None: ...

class QSOption(Option):
    func: QSFunction
    rate: int

class QuickStartRequestOption(QSOption):
    ttl: timedelta
    nonce: int
    def __init__(self, code: OptionNumber, length: int, type: OptionType, func: QSFunction, rate: int, ttl: timedelta, nonce: int) -> None: ...

class QuickStartReportOption(QSOption):
    nonce: int
    def __init__(self, code: OptionNumber, length: int, type: OptionType, func: QSFunction, rate: int, nonce: int) -> None: ...
