from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address
from pcapkit.const.reg.apptype import AppType
from pcapkit.const.tcp.checksum import Checksum
from pcapkit.const.tcp.flags import Flags as TCP_Flags
from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
from pcapkit.const.tcp.option import Option as OptionNumber
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.data import Data
from typing import Optional, Union

IPAddress = Union[IPv4Address, IPv6Address]

class Flags(Data):
    cwr: bool
    ece: bool
    urg: bool
    ack: bool
    psh: bool
    rst: bool
    syn: bool
    fin: bool
    def __init__(self, cwr: bool, ece: bool, urg: bool, ack: bool, psh: bool, rst: bool, syn: bool, fin: bool) -> None: ...

class TCP(Data):
    srcport: AppType
    dstport: AppType
    seq: int
    ack: int
    hdr_len: int
    flags: Flags
    window_size: int
    checksum: bytes
    urgent_pointer: int
    options: OrderedMultiDict[OptionNumber, Option]
    connection: TCP_Flags
    def __init__(self, srcport: AppType, dstport: AppType, seq: int, ack: int, hdr_len: int, flags: Flags, window_size: int, checksum: bytes, urgent_pointer: int) -> None: ...

class Option(Data):
    kind: OptionNumber
    length: int

class UnassignedOption(Option):
    data: bytes
    def __init__(self, kind: OptionNumber, length: int, data: bytes) -> None: ...

class EndOfOptionList(Option):
    def __init__(self, kind: OptionNumber, length: int) -> None: ...

class NoOperation(Option):
    def __init__(self, kind: OptionNumber, length: int) -> None: ...

class MaximumSegmentSize(Option):
    mss: int
    def __init__(self, kind: OptionNumber, length: int, mss: int) -> None: ...

class WindowScale(Option):
    shift: int
    def __init__(self, kind: OptionNumber, length: int, shift: int) -> None: ...

class SACKPermitted(Option):
    def __init__(self, kind: OptionNumber, length: int) -> None: ...

class SACKBlock(Data):
    left: int
    right: int
    def __init__(self, left: int, right: int) -> None: ...

class SACK(Option):
    sack: tuple[SACKBlock, ...]
    def __init__(self, kind: OptionNumber, length: int, sack: tuple[SACKBlock, ...]) -> None: ...

class Echo(Option):
    data: bytes
    def __init__(self, kind: OptionNumber, length: int, data: bytes) -> None: ...

class EchoReply(Option):
    data: bytes
    def __init__(self, kind: OptionNumber, length: int, data: bytes) -> None: ...

class Timestamps(Option):
    timestamp: int
    echo: int
    def __init__(self, kind: OptionNumber, length: int, timestamp: int, echo: int) -> None: ...

class PartialOrderConnectionPermitted(Option):
    def __init__(self, kind: OptionNumber, length: int) -> None: ...

class PartialOrderServiceProfile(Option):
    start: bool
    end: bool
    def __init__(self, kind: OptionNumber, length: int, start: bool, end: bool) -> None: ...

class CC(Option):
    cc: int
    def __init__(self, kind: OptionNumber, length: int, cc: int) -> None: ...

class CCNew(Option):
    cc: int
    def __init__(self, kind: OptionNumber, length: int, cc: int) -> None: ...

class CCEcho(Option):
    cc: int
    def __init__(self, kind: OptionNumber, length: int, cc: int) -> None: ...

class AlternateChecksumRequest(Option):
    chksum: Checksum
    def __init__(self, kind: OptionNumber, length: int, chksum: Checksum) -> None: ...

class AlternateChecksumData(Option):
    data: bytes
    def __init__(self, kind: OptionNumber, length: int, data: bytes) -> None: ...

class MD5Signature(Option):
    digest: bytes
    def __init__(self, kind: OptionNumber, length: int, digest: bytes) -> None: ...

class QuickStartResponse(Option):
    req_rate: int
    ttl_diff: int
    nonce: int
    def __init__(self, kind: OptionNumber, length: int, req_rate: int, ttl_diff: int, nonce: int) -> None: ...

class UserTimeout(Option):
    timeout: timedelta
    def __init__(self, kind: OptionNumber, length: int, timeout: timedelta) -> None: ...

class Authentication(Option):
    key_id: int
    next_key_id: int
    mac: bytes
    def __init__(self, kind: OptionNumber, length: int, key_id: int, next_key_id: int, mac: bytes) -> None: ...

class FastOpenCookie(Option):
    cookie: bytes
    def __init__(self, kind: OptionNumber, length: int, cookie: bytes) -> None: ...

class MPTCP(Option):
    subtype: MPTCPOption

class MPTCPUnknown(MPTCP):
    data: bytes
    def __init__(self, kind: OptionNumber, length: int, subtype: MPTCPOption, data: bytes) -> None: ...

class MPTCPCapableFlag(Data):
    req: bool
    ext: bool
    hsa: bool
    def __init__(self, req: bool, ext: bool, hsa: bool) -> None: ...

class MPTCPCapable(MPTCP):
    version: int
    flags: MPTCPCapableFlag
    skey: int
    rkey: Optional[int]
    def __init__(self, kind: OptionNumber, length: int, subtype: MPTCPOption, version: int, flags: MPTCPCapableFlag, skey: int, rkey: Optional[int]) -> None: ...

class MPTCPJoin(MPTCP):
    connection: TCP_Flags

class MPTCPJoinSYN(MPTCPJoin):
    backup: bool
    addr_id: int
    token: int
    nonce: int
    def __init__(self, kind: OptionNumber, length: int, subtype: MPTCPOption, connection: TCP_Flags, backup: bool, addr_id: int, token: int, nonce: int) -> None: ...

class MPTCPJoinSYNACK(MPTCPJoin):
    backup: bool
    addr_id: int
    hmac: bytes
    nonce: int
    def __init__(self, kind: OptionNumber, length: int, subtype: MPTCPOption, connection: TCP_Flags, backup: bool, addr_id: int, hmac: bytes, nonce: int) -> None: ...

class MPTCPJoinACK(MPTCPJoin):
    hmac: bytes
    def __init__(self, kind: OptionNumber, length: int, subtype: MPTCPOption, connection: TCP_Flags, hmac: bytes) -> None: ...

class MPTCPDSS(MPTCP):
    data_fin: bool
    ack: Optional[int]
    dsn: Optional[int]
    ssn: Optional[int]
    dl_len: Optional[int]
    checksum: Optional[bytes]
    def __init__(self, kind: OptionNumber, length: int, subtype: MPTCPOption, data_fin: bool, ack: Optional[int], dsn: Optional[int], ssn: Optional[int], dl_len: Optional[int], checksum: Optional[bytes]) -> None: ...

class MPTCPAddAddress(MPTCP):
    version: int
    addr_id: int
    addr: IPAddress
    port: Optional[int]
    def __init__(self, kind: OptionNumber, length: int, subtype: MPTCPOption, version: int, addr_id: int, addr: IPAddress, port: Optional[int]) -> None: ...

class MPTCPRemoveAddress(MPTCP):
    addr_id: tuple[int, ...]
    def __init__(self, kind: OptionNumber, length: int, subtype: MPTCPOption, addr_id: tuple[int, ...]) -> None: ...

class MPTCPPriority(MPTCP):
    backup: bool
    addr_id: Optional[int]
    def __init__(self, kind: OptionNumber, length: int, subtype: MPTCPOption, backup: bool, addr_id: Optional[int]) -> None: ...

class MPTCPFallback(MPTCP):
    dsn: int
    def __init__(self, kind: OptionNumber, length: int, subtype: MPTCPOption, dsn: int) -> None: ...

class MPTCPFastclose(MPTCP):
    rkey: int
    def __init__(self, kind: OptionNumber, length: int, subtype: MPTCPOption, rkey: int) -> None: ...
