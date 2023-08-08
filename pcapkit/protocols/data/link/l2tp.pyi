from pcapkit.const.l2tp.type import Type
from pcapkit.protocols.data.data import Data
from typing import Optional

class Flags(Data):
    type: Type
    len: bool
    seq: bool
    offset: bool
    prio: bool
    def __init__(self, type: Type, len: bool, seq: bool, offset: bool, prio: bool) -> None: ...

class L2TP(Data):
    flags: Flags
    version: int
    length: Optional[int]
    tunnelid: int
    sessionid: int
    ns: Optional[int]
    nr: Optional[int]
    offset: Optional[int]
    hdr_len: int
    def __init__(self, flags: Flags, version: int, length: Optional[int], tunnelid: int, sessionid: int, ns: Optional[int], nr: Optional[int], offset: Optional[int]) -> None: ...
