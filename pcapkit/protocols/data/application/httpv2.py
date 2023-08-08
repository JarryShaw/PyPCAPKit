# -*- coding: utf-8 -*-
"""data model for HTTP/2 protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.utilities.compat import NotRequired

if TYPE_CHECKING:
    from typing import Optional

    from typing_extensions import Literal

    from pcapkit.const.http.error_code import ErrorCode
    from pcapkit.const.http.frame import Frame
    from pcapkit.const.http.setting import Setting
    from pcapkit.corekit.multidict import OrderedMultiDict
    from pcapkit.protocols.schema.application.httpv2 import FrameType

__all__ = [
    'HTTP',

    'Flags',
    'DataFrameFlags', 'HeadersFrameFlags', 'SettingsFrameFlags',
    'PushPromiseFrameFlags', 'PingFrameFlags', 'ContinuationFrameFlags',

    'UnassignedFrame', 'DataFrame', 'HeadersFrame', 'PriorityFrame',
    'RSTStreamFrame', 'SettingsFrame', 'PushPromiseFrame', 'PingFrame',
    'GoawayFrame', 'WindowUpdateFrame', 'ContinuationFrame',
]


class Flags(Data):
    """Data model for HTTP/2 flags."""

    #: Flags as in combination value.
    __value__: 'FrameType.Flags' = NotRequired  # type: ignore[assignment]


class HTTP(Data):
    """Data model for HTTP/2 protocol."""

    #: Length.
    length: 'int'
    #: Frame type.
    type: 'Frame'
    #: Flags.
    flags: 'Optional[Flags]'
    #: Stream ID.
    sid: 'int'


@info_final
class UnassignedFrame(HTTP):
    """Data model for HTTP/2 unassigned frame."""

    #: Flags.
    flags: 'Literal[None]'
    #: Frame payload.
    data: 'bytes'


@info_final
class DataFrameFlags(Flags):
    """Data model for HTTP/2 ``DATA`` frame flags."""

    #: ``END_STREAM`` flag.
    END_STREAM: 'bool'  # bit 0
    #: ``PADDED`` flag.
    PADDED: 'bool'      # bit 3


@info_final
class DataFrame(HTTP):
    """Data model for HTTP/2 ``DATA`` frame."""

    #: Flags.
    flags: 'DataFrameFlags'
    #: Padded length.
    pad_len: 'int'
    #: Frame payload.
    data: 'bytes'


@info_final
class HeadersFrameFlags(Flags):
    """Data model for HTTP/2 ``HEADERS`` frame flags."""

    #: ``END_STREAM`` flag.
    END_STREAM: 'bool'   # bit 0
    #: ``END_HEADERS`` flag.
    END_HEADERS: 'bool'  # bit 2
    #: ``PADDED`` flag.
    PADDED: 'bool'       # bit 3
    #: ``PRIORITY`` flag.
    PRIORITY: 'bool'     # bit 5


@info_final
class HeadersFrame(HTTP):
    """Data model for HTTP/2 ``HEADERS`` frame."""

    #: Flags.
    flags: 'HeadersFrameFlags'
    #: Padded length.
    pad_len: 'int'
    #: Exclusive dependency.
    excl_dependency: 'bool'
    #: Stream dependency.
    stream_dependency: 'int'
    #: Weight.
    weight: 'int'
    #: Header block fragment.
    fragment: 'bytes'


@info_final
class PriorityFrame(HTTP):
    """Data model for HTTP/2 ``PRIORITY`` frame."""

    #: Flags.
    flags: 'Literal[None]'
    #: Exclusive dependency.
    excl_dependency: 'bool'
    #: Stream dependency.
    stream_dependency: 'int'
    #: Weight.
    weight: 'int'


@info_final
class RSTStreamFrame(HTTP):
    """Data model for HTTP/2 ``RST_STREAM`` frame."""

    #: Flags.
    flags: 'Literal[None]'
    #: Error code.
    error: 'ErrorCode'


@info_final
class SettingsFrameFlags(Flags):
    """Data model for HTTP/2 ``SETTINGS`` frame flags."""

    #: ``ACK`` flag.
    ACK: 'bool'  # bit 0


@info_final
class SettingsFrame(HTTP):
    """Data model for HTTP/2 ``SETTINGS`` frame."""

    #: Flags.
    flags: 'SettingsFrameFlags'
    #: Settings.
    settings: 'OrderedMultiDict[Setting, int]'


@info_final
class PushPromiseFrameFlags(Flags):
    """Data model for HTTP/2 ``PUSH_PROMISE`` frame flags."""

    #: ``END_HEADERS`` flag.
    END_HEADERS: 'bool'  # bit 2
    #: ``PADDED`` flag.
    PADDED: 'bool'       # bit 3


@info_final
class PushPromiseFrame(HTTP):
    """Data model for HTTP/2 ``PUSH_PROMISE`` frame."""

    #: Flags.
    flags: 'PushPromiseFrameFlags'
    #: Padded length.
    pad_len: 'int'
    #: Promised stream ID.
    promised_sid: 'int'
    #: Header block fragment.
    fragment: 'bytes'


@info_final
class PingFrameFlags(Flags):
    """Data model for HTTP/2 ``PING`` frame flags."""

    #: ``ACK`` flag.
    ACK: 'bool'  # bit 0


@info_final
class PingFrame(HTTP):
    """Data model for HTTP/2 ``PING`` frame."""

    #: Flags.
    flags: 'PingFrameFlags'
    #: Opaque data.
    data: 'bytes'


@info_final
class GoawayFrame(HTTP):
    """Data model for HTTP/2 ``GOAWAY`` frame."""

    #: Flags.
    flags: 'Literal[None]'
    #: Last stream ID.
    last_sid: 'int'
    #: Error code.
    error: 'ErrorCode'
    #: Additional debug data.
    debug_data: 'bytes'


@info_final
class WindowUpdateFrame(HTTP):
    """Data moddel for HTTP/2 ``WINDOW_UPDATE`` frame."""

    #: Flags.
    flags: 'Literal[None]'
    #: Window size increment.
    increment: 'int'


@info_final
class ContinuationFrameFlags(Flags):
    """Data model for HTTP/2 ``CONTINUATION`` frame flags."""

    #: ``END_HEADERS`` flag.
    END_HEADERS: 'bool'  # bit 2


@info_final
class ContinuationFrame(HTTP):
    """Data model for HTTP/2 ``CONTINUATION`` frame."""

    #: Flags.
    flags: 'ContinuationFrameFlags'
    #: Header block fragment.
    fragment: 'bytes'
