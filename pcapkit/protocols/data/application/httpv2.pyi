from pcapkit.const.http.error_code import ErrorCode
from pcapkit.const.http.frame import Frame
from pcapkit.const.http.setting import Setting
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.schema.application.httpv2 import FrameType
from typing import Optional
from typing_extensions import Literal

class Flags(Data):
    __value__: FrameType.Flags

class HTTP(Data):
    length: int
    type: Frame
    flags: Optional[Flags]
    sid: int

class UnassignedFrame(HTTP):
    flags: Literal[None]
    data: bytes
    def __init__(self, length: int, type: Frame, flags: Literal[None], sid: int, data: bytes) -> None: ...

class DataFrameFlags(Flags):
    END_STREAM: bool
    PADDED: bool
    def __init__(self, END_STREAM: bool, PADDED: bool) -> None: ...

class DataFrame(HTTP):
    flags: DataFrameFlags
    pad_len: int
    data: bytes
    def __init__(self, length: int, type: Frame, flags: DataFrameFlags, pad_len: int, sid: int, data: bytes) -> None: ...

class HeadersFrameFlags(Flags):
    END_STREAM: bool
    END_HEADERS: bool
    PADDED: bool
    PRIORITY: bool
    def __init__(self, END_STREAM: bool, END_HEADERS: bool, PADDED: bool, PRIORITY: bool) -> None: ...

class HeadersFrame(HTTP):
    flags: HeadersFrameFlags
    pad_len: int
    excl_dependency: bool
    stream_dependency: int
    weight: int
    fragment: bytes
    def __init__(self, length: int, type: Frame, flags: HeadersFrameFlags, pad_len: int, sid: int, excl_dependency: bool, stream_dependency: int, weight: int, fragment: bytes) -> None: ...

class PriorityFrame(HTTP):
    flags: Literal[None]
    excl_dependency: bool
    stream_dependency: int
    weight: int
    def __init__(self, length: int, type: Frame, flags: Literal[None], sid: int, excl_dependency: bool, stream_dependency: int, weight: int) -> None: ...

class RSTStreamFrame(HTTP):
    flags: Literal[None]
    error: ErrorCode
    def __init__(self, length: int, type: Frame, flags: Literal[None], sid: int, error: int) -> None: ...

class SettingsFrameFlags(Flags):
    ACK: bool
    def __init__(self, ACK: bool) -> None: ...

class SettingsFrame(HTTP):
    flags: SettingsFrameFlags
    settings: OrderedMultiDict[Setting, int]
    def __init__(self, length: int, type: Frame, flags: Optional[Flags], sid: int, settings: OrderedMultiDict[Setting, int]) -> None: ...

class PushPromiseFrameFlags(Flags):
    END_HEADERS: bool
    PADDED: bool
    def __init__(self, END_HEADERS: bool, PADDED: bool) -> None: ...

class PushPromiseFrame(HTTP):
    flags: PushPromiseFrameFlags
    pad_len: int
    promised_sid: int
    fragment: bytes
    def __init__(self, length: int, type: Frame, flags: Optional[Flags], pad_len: int, sid: int, promised_sid: int, fragment: bytes) -> None: ...

class PingFrameFlags(Flags):
    ACK: bool
    def __init__(self, ACK: bool) -> None: ...

class PingFrame(HTTP):
    flags: PingFrameFlags
    data: bytes
    def __init__(self, length: int, type: Frame, flags: Optional[Flags], sid: int, data: bytes) -> None: ...

class GoawayFrame(HTTP):
    flags: Literal[None]
    last_sid: int
    error: ErrorCode
    debug_data: bytes
    def __init__(self, length: int, type: Frame, flags: Optional[Flags], sid: int, last_sid: int, error: int, debug_data: bytes) -> None: ...

class WindowUpdateFrame(HTTP):
    flags: Literal[None]
    increment: int
    def __init__(self, length: int, type: Frame, flags: Optional[Flags], sid: int, increment: int) -> None: ...

class ContinuationFrameFlags(Flags):
    END_HEADERS: bool
    def __init__(self, END_HEADERS: bool) -> None: ...

class ContinuationFrame(HTTP):
    flags: ContinuationFrameFlags
    fragment: bytes
    def __init__(self, length: int, type: Frame, flags: Optional[Flags], sid: int, fragment: bytes) -> None: ...
