from ipaddress import IPv4Address
from pcapkit.const.ospf.authentication import Authentication
from pcapkit.const.ospf.packet import Packet
from pcapkit.protocols.data.data import Data

class CrytographicAuthentication(Data):
    key_id: int
    len: int
    seq: int
    def __init__(self, key_id: int, len: int, seq: int) -> None: ...

class OSPF(Data):
    version: int
    type: Packet
    len: int
    router_id: IPv4Address
    area_id: IPv4Address
    chksum: bytes
    autype: Authentication
    auth: bytes | CrytographicAuthentication
    def __init__(self, version: int, type: Packet, len: int, router_id: IPv4Address, area_id: IPv4Address, chksum: bytes, autype: Authentication) -> None: ...
