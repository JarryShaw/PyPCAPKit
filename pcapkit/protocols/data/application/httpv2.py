# -*- coding: utf-8 -*-
"""data model for HTTP/2 protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.data.application.http import HTTP as DataType_HTTP

if TYPE_CHECKING:
    from typing import Optional

    from typing_extensions import Literal

    from pcapkit.const.http.error_code import ErrorCode
    from pcapkit.const.http.frame import Frame
    from pcapkit.const.http.setting import Setting
    from pcapkit.corekit.multidict import OrderedMultiDict

__all__ = [
    'HTTP',

    'Flags',
    'DataFrameFlags', 'HeadersFrameFlags', 'SettingsFrameFlags',
    'PushPromiseFrameFlags', 'PingFrameFlags', 'ContinuationFrameFlags',

    'UnassignedFrame', 'DataFrame', 'HeadersFrame', 'PriorityFrame',
    'RstStreamFrame', 'SettingsFrame', 'PushPromiseFrame', 'PingFrame',
    'GoawayFrame', 'WindowUpdateFrame', 'ContinuationFrame',
]


class Flags(Info):
    """Data model for HTTP/2 flags."""


class HTTP(DataType_HTTP):
    """Data model for HTTP/2 protocol."""

    #: Length.
    length: 'int'
    #: Frame type.
    type: 'Frame'
    #: Flags.
    flags: 'Optional[Flags]'
    #: Stream ID.
    sid: 'int'


class UnassignedFrame(HTTP):
    """Data model for HTTP/2 unassigned frame."""

    #: Flags.
    flags: 'Literal[None]'
    #: Frame payload.
    data: 'Optional[bytes]'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Literal[None]', sid: 'int', data: 'Optional[bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class DataFrameFlags(Flags):
    """Data model for HTTP/2 ``DATA`` frame flags."""

    #: ``END_STREAM`` flag.
    END_STREAM: 'bool'  # bit 0
    #: ``PADDED`` flag.
    PADDED: 'bool'      # bit 3

    if TYPE_CHECKING:
        def __init__(self, END_STREAM: 'bool', PADDED: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class DataFrame(HTTP):
    """Data model for HTTP/2 ``DATA`` frame."""

    #: Flags.
    flags: 'DataFrameFlags'
    #: Padded length.
    pad_len: 'int'
    #: Frame payload.
    data: 'Optional[bytes]'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Optional[Flags]', pad_len: 'int', sid: 'int', data: 'Optional[bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


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

    if TYPE_CHECKING:
        def __init__(self, END_STREAM: 'bool', END_HEADERS: 'bool', PADDED: 'bool', PRIORITY: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class HeadersFrame(HTTP):
    """Data model for HTTP/2 ``HEADERS`` frame."""

    #: Flags.
    flags: 'HeadersFrameFlags'
    #: Padded length.
    pad_len: 'int'
    #: Exclusive dependency.
    excl_dependency: 'Optional[bool]'
    #: Stream dependency.
    stream_dependency: 'Optional[int]'
    #: Weight.
    weight: 'Optional[int]'
    #: Header block fragment.
    fragment: 'Optional[bytes]'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Optional[Flags]', pad_len: 'int', sid: 'int', excl_dependency: 'Optional[bool]', stream_dependency: 'Optional[int]', weight: 'Optional[int]', fragment: 'Optional[bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


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

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Literal[None]', sid: 'int', excl_dependency: 'bool', stream_dependency: 'int', weight: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class RstStreamFrame(HTTP):
    """Data model for HTTP/2 ``RST_STREAM`` frame."""

    #: Flags.
    flags: 'Literal[None]'
    #: Error code.
    error: 'ErrorCode'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Literal[None]', sid: 'int', error: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class SettingsFrameFlags(Flags):
    """Data model for HTTP/2 ``SETTINGS`` frame flags."""

    #: ``ACK`` flag.
    ACK: 'bool'  # bit 0

    if TYPE_CHECKING:
        def __init__(self, ACK: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class SettingsFrame(HTTP):
    """Data model for HTTP/2 ``SETTINGS`` frame."""

    #: Flags.
    flags: 'SettingsFrameFlags'
    #: Settings.
    settings: 'OrderedMultiDict[Setting, int]'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Optional[Flags]', sid: 'int', settings: 'OrderedMultiDict[Setting, int]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class PushPromiseFrameFlags(Flags):
    """Data model for HTTP/2 ``PUSH_PROMISE`` frame flags."""

    #: ``END_HEADERS`` flag.
    END_HEADERS: 'bool'  # bit 2
    #: ``PADDED`` flag.
    PADDED: 'bool'       # bit 3

    if TYPE_CHECKING:
        def __init__(self, END_HEADERS: 'bool', PADDED: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class PushPromiseFrame(HTTP):
    """Data model for HTTP/2 ``PUSH_PROMISE`` frame."""

    #: Flags.
    flags: 'PushPromiseFrameFlags'
    #: Padded length.
    pad_len: 'int'
    #: Promised stream ID.
    promised_sid: 'int'
    #: Header block fragment.
    fragment: 'Optional[bytes]'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Optional[Flags]', pad_len: 'int', sid: 'int', promised_sid: 'int', fragment: 'Optional[bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class PingFrameFlags(Flags):
    """Data model for HTTP/2 ``PING`` frame flags."""

    #: ``ACK`` flag.
    ACK: 'bool'  # bit 0

    if TYPE_CHECKING:
        def __init__(self, ACK: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class PingFrame(HTTP):
    """Data model for HTTP/2 ``PING`` frame."""

    #: Flags.
    flags: 'PingFrameFlags'
    #: Opaque data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Optional[Flags]', sid: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class GoawayFrame(HTTP):
    """Data model for HTTP/2 ``GOAWAY`` frame."""

    #: Flags.
    flags: 'Literal[None]'
    #: Last stream ID.
    last_sid: 'int'
    #: Error code.
    error: 'ErrorCode'
    #: Additional debug data.
    debug_data: 'Optional[bytes]'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Optional[Flags]', sid: 'int', last_sid: 'int', error: 'int', debug_data: 'Optional[bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class WindowUpdateFrame(HTTP):
    """Data moddel for HTTP/2 ``WINDOW_UPDATE`` frame."""

    #: Flags.
    flags: 'Literal[None]'
    #: Window size increment.
    increment: 'int'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Optional[Flags]', sid: 'int', increment: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class ContinuationFrameFlags(Flags):
    """Data model for HTTP/2 ``CONTINUATION`` frame flags."""

    #: ``END_HEADERS`` flag.
    END_HEADERS: 'bool'  # bit 2

    if TYPE_CHECKING:
        def __init__(self, END_HEADERS: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class ContinuationFrame(HTTP):
    """Data model for HTTP/2 ``CONTINUATION`` frame."""

    #: Flags.
    flags: 'ContinuationFrameFlags'
    #: Header block fragment.
    fragment: 'Optional[bytes]'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Optional[Flags]', sid: 'int', fragment: 'Optional[bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin
