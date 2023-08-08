from pcapkit.const.reg.apptype import AppType
from pcapkit.protocols.data.data import Data

class UDP(Data):
    srcport: AppType
    dstport: AppType
    len: int
    checksum: bytes
    def __init__(self, srcport: AppType, dstport: AppType, len: int, checksum: bytes) -> None: ...
