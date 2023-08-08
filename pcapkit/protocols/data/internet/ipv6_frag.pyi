from pcapkit.const.reg.transtype import TransType
from pcapkit.protocols.data.data import Data

class IPv6_Frag(Data):
    next: TransType
    offset: int
    mf: bool
    id: int
    def __init__(self, next: TransType, offset: int, mf: bool, id: int) -> None: ...
