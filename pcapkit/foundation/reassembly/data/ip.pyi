from ipaddress import IPv4Address, IPv6Address
from pcapkit.const.reg.transtype import TransType
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.compat import Tuple
from typing import Generic, Optional, TypeVar, overload
from typing_extensions import Literal, TypeAlias

AT = TypeVar('AT', 'IPv4Address', 'IPv6Address')
BufferID: TypeAlias = Tuple[AT, AT, int, 'TransType']

class Packet(Info, Generic[AT]):
    bufid: BufferID
    num: int
    fo: int
    ihl: int
    mf: bool
    tl: int
    header: bytes
    payload: bytearray
    def __init__(self, bufid: tuple[AT, AT, int, TransType], num: int, fo: int, ihl: int, mf: bool, tl: int, header: bytes, payload: bytearray) -> None: ...

class DatagramID(Info, Generic[AT]):
    src: AT
    dst: AT
    id: int
    proto: TransType
    def __init__(self, src: AT, dst: AT, id: int, proto: TransType) -> None: ...

class Datagram(Info, Generic[AT]):
    completed: bool
    id: DatagramID[AT]
    index: tuple[int, ...]
    header: bytes
    payload: bytes | tuple[bytes, ...]
    packet: Optional[Protocol]
    @overload
    def __init__(self, completed: Literal[True], id: DatagramID[AT], index: tuple[int, ...], header: bytes, payload: bytes, packet: Protocol) -> None: ...
    @overload
    def __init__(self, completed: Literal[False], id: DatagramID[AT], index: tuple[int, ...], header: bytes, payload: tuple[bytes, ...], packet: None) -> None: ...

class Buffer(Info, Generic[AT]):
    TDL: int
    RCVBT: bytearray
    index: list[int]
    header: bytes
    datagram: bytearray
    def __init__(self, TDL: int, RCVBT: bytearray, index: list[int], header: bytes, datagram: bytearray) -> None: ...
