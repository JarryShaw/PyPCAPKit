from pcapkit.const.reg.transtype import TransType
from pcapkit.protocols.data.data import Data

class AH(Data):
    next: TransType
    length: int
    spi: int
    seq: int
    icv: bytes
    def __init__(self, next: TransType, length: int, spi: int, seq: int, icv: bytes) -> None: ...
