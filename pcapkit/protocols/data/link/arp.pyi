from ipaddress import IPv4Address, IPv6Address
from pcapkit.const.arp.hardware import Hardware
from pcapkit.const.arp.operation import Operation
from pcapkit.const.reg.ethertype import EtherType
from pcapkit.protocols.data.data import Data

class Address(Data):
    hardware: str
    protocol: str | IPv4Address | IPv6Address
    def __init__(self, hardware: str, protocol: str | IPv4Address | IPv6Address) -> None: ...

class Type(Data):
    hardware: Hardware
    protocol: EtherType | str
    def __init__(self, hardware: Hardware, protocol: EtherType | str) -> None: ...

class ARP(Data):
    htype: Hardware
    ptype: EtherType
    hlen: int
    plen: int
    oper: Operation
    sha: str
    spa: str | IPv4Address | IPv6Address
    tha: str
    tpa: str | IPv4Address | IPv6Address
    len: int
    def __init__(self, htype: Hardware, ptype: EtherType, hlen: int, plen: int, oper: Operation, sha: str, spa: str | IPv4Address | IPv6Address, tha: str, tpa: str | IPv4Address | IPv6Address, len: int) -> None: ...
