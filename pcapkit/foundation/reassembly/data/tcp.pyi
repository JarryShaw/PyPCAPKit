from ipaddress import IPv4Address, IPv6Address
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.compat import Tuple
from typing import Generic, Optional, TypeVar, overload
from typing_extensions import Literal, TypeAlias

IPAddress = TypeVar('IPAddress', 'IPv4Address', 'IPv6Address')
BufferID: TypeAlias = Tuple[IPAddress, int, IPAddress, int]

class Packet(Info):
    bufid: BufferID
    dsn: int
    ack: int
    num: int
    syn: bool
    fin: bool
    rst: bool
    len: int
    first: int
    last: int
    header: bytes
    payload: bytearray
    def __init__(self, bufid: BufferID, dsn: int, ack: int, num: int, syn: bool, fin: bool, rst: bool, len: int, first: int, last: int, header: bytes, payload: bytearray) -> None: ...

class DatagramID(Info, Generic[IPAddress]):
    src: tuple[IPAddress, int]
    dst: tuple[IPAddress, int]
    ack: int
    def __init__(self, src: tuple[IPAddress, int], dst: tuple[IPAddress, int], ack: int) -> None: ...

class Datagram(Info, Generic[IPAddress]):
    completed: bool
    id: DatagramID[IPAddress]
    index: tuple[int, ...]
    header: bytes
    payload: bytes | tuple[bytes, ...]
    packet: Optional[Protocol]
    @overload
    def __init__(self, completed: Literal[True], id: DatagramID[IPAddress], index: tuple[int, ...], header: bytes, payload: bytes, packet: Protocol) -> None: ...
    @overload
    def __init__(self, completed: Literal[False], id: DatagramID[IPAddress], index: tuple[int, ...], header: bytes, payload: tuple[bytes, ...], packet: None) -> None: ...

class HoleDiscriptor(Info):
    first: int
    last: int
    def __init__(self, first: int, last: int) -> None: ...

class Fragment(Info):
    ind: list[int]
    isn: int
    len: int
    raw: bytearray
    def __init__(self, ind: list[int], isn: int, len: int, raw: bytearray) -> None: ...

class Buffer(Info):
    hdl: list[HoleDiscriptor]
    hdr: bytes
    ack: dict[int, Fragment]
    def __init__(self, hdl: list[HoleDiscriptor], hdr: bytes, ack: dict[int, Fragment]) -> None: ...
