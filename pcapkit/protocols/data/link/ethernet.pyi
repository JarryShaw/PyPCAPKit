from pcapkit.const.reg.ethertype import EtherType
from pcapkit.protocols.data.data import Data

class Ethernet(Data):
    dst: str
    src: str
    type: EtherType
    def __init__(self, dst: str, src: str, type: EtherType) -> None: ...
