from pcapkit.const.reg.ethertype import EtherType
from pcapkit.const.vlan.priority_level import PriorityLevel
from pcapkit.protocols.data.data import Data

class TCI(Data):
    pcp: PriorityLevel
    dei: bool
    vid: int
    def __init__(self, pcp: PriorityLevel, dei: bool, vid: int) -> None: ...

class VLAN(Data):
    tci: TCI
    type: EtherType
    def __init__(self, tci: TCI, type: EtherType) -> None: ...
