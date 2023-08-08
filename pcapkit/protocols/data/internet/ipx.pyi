from pcapkit.const.ipx.packet import Packet
from pcapkit.const.ipx.socket import Socket
from pcapkit.protocols.data.data import Data

class Address(Data):
    network: str
    node: str
    socket: Socket
    addr: str
    def __init__(self, network: str, node: str, socket: Socket, addr: str) -> None: ...

class IPX(Data):
    chksum: bytes
    len: int
    count: int
    type: Packet
    dst: Address
    src: Address
    def __init__(self, chksum: bytes, len: int, count: int, type: Packet, dst: Address, src: Address) -> None: ...
