from pcapkit.protocols.data.data import Data
from typing import Optional

class Raw(Data):
    protocol: Optional[int]
    packet: bytes
    error: Optional[Exception]
    def __init__(self, protocol: Optional[int], packet: bytes, error: Optional[Exception]) -> None: ...
