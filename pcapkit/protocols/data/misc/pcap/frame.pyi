from datetime import datetime
from decimal import Decimal
from pcapkit.protocols.data.data import Data

class FrameInfo(Data):
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int
    def __init__(self, ts_sec: int, ts_usec: int, incl_len: int, orig_len: int) -> None: ...

class Frame(Data):
    frame_info: FrameInfo
    time: datetime
    number: int
    time_epoch: Decimal
    len: int
    cap_len: int
    protocols: str
    def __init__(self, frame_info: FrameInfo, time: datetime, number: int, time_epoch: Decimal, len: int, cap_len: int) -> None: ...
