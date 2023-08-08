from pcapkit.const.reg.linktype import LinkType
from pcapkit.corekit.version import VersionInfo
from pcapkit.protocols.data.data import Data
from typing_extensions import Literal

class MagicNumber(Data):
    data: bytes
    byteorder: Literal['big', 'little']
    nanosecond: bool
    def __init__(self, data: bytes, byteorder: Literal['big', 'little'], nanosecond: bool) -> None: ...

class Header(Data):
    magic_number: MagicNumber
    version: VersionInfo
    thiszone: int
    sigfigs: int
    snaplen: int
    network: LinkType
    def __init__(self, magic_number: MagicNumber, version: VersionInfo, thiszone: int, sigfigs: int, snaplen: int, network: LinkType) -> None: ...
