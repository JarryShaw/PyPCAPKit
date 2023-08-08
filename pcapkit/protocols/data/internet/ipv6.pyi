from ipaddress import IPv6Address
from pcapkit.const.reg.transtype import TransType
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Packet
from typing import Any
from typing_extensions import Literal

class IPv6(Data):
    version: Literal[6]
    label: int
    payload: int
    next: TransType
    limit: int
    src: IPv6Address
    dst: IPv6Address
    fragment: Packet
    protocol: TransType
    hdr_len: int
    raw_len: int
    def __new__(cls, *args: Any, **kwargs: Any) -> IPv6: ...
