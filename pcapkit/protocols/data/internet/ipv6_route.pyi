from ipaddress import IPv6Address
from pcapkit.const.ipv6.routing import Routing
from pcapkit.const.reg.transtype import TransType
from pcapkit.protocols.data.data import Data

class IPv6_Route(Data):
    next: TransType
    length: int
    type: Routing
    seg_left: int

class UnknownType(IPv6_Route):
    data: bytes
    def __init__(self, next: TransType, length: int, type: Routing, seg_left: int, data: bytes) -> None: ...

class SourceRoute(IPv6_Route):
    ip: tuple[IPv6Address, ...]
    def __init__(self, next: TransType, length: int, type: Routing, seg_left: int, ip: tuple[IPv6Address, ...]) -> None: ...

class Type2(IPv6_Route):
    ip: IPv6Address
    def __init__(self, next: TransType, length: int, type: Routing, seg_left: int, ip: IPv6Address) -> None: ...

class RPL(IPv6_Route):
    cmpr_i: int
    cmpr_e: int
    pad: int
    ip: tuple[IPv6Address | bytes, ...]
    def __init__(self, next: TransType, length: int, type: Routing, seg_left: int, cmpr_i: int, cmpr_e: int, pad: int, ip: tuple[IPv6Address | bytes, ...]) -> None: ...
