# -*- coding: utf-8 -*-
"""data model for HTTP/2 protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing import Iterator

    from pcapkit.const.http.error_code import ErrorCode
    from pcapkit.const.http.frame import Frame
    from pcapkit.const.http.setting import Setting
    from pcapkit.protocols.schema.application.httpv2 import FrameType

__all__ = [
    'HTTP',

    'Flags', 'Settings',
    'DataFrameFlags', 'HeadersFrameFlags', 'SettingsFrameFlags',
    'PushPromiseFrameFlags', 'PingFrameFlags', 'ContinuationFrameFlags',

    'UnassignedFrame', 'DataFrame', 'HeadersFrame', 'PriorityFrame',
    'RSTStreamFrame', 'SettingsFrame', 'PushPromiseFrame', 'PingFrame',
    'GoawayFrame', 'WindowUpdateFrame', 'ContinuationFrame',
]


class Flags(Data):
    """Data model for HTTP/2 flags."""

    if TYPE_CHECKING:
        #: Flags as in combination value, bits the frame type leaves
        #: undefined included.
        __value__: 'FrameType.Flags'


class HTTP(Protocol):
    """Data model for HTTP/2 protocol."""

    #: Length of the frame payload, the 9-octet header excluded.
    length: 'int'
    #: Frame type.
    type: 'Frame'
    #: Flags.
    flags: 'Flags'
    #: Reserved bit of the frame header.
    reserved: 'int'
    #: Stream ID.
    sid: 'int'


@info_final
class UnassignedFrame(HTTP):
    """Data model for HTTP/2 unassigned frame."""

    #: Flags.
    flags: 'Flags'
    #: Frame payload.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Flags', reserved: 'int', sid: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class DataFrameFlags(Flags):
    """Data model for HTTP/2 ``DATA`` frame flags."""

    #: ``END_STREAM`` flag.
    END_STREAM: 'bool'  # bit 0
    #: ``PADDED`` flag.
    PADDED: 'bool'      # bit 3

    if TYPE_CHECKING:
        def __init__(self, END_STREAM: 'bool', PADDED: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class DataFrame(HTTP):
    """Data model for HTTP/2 ``DATA`` frame."""

    #: Flags.
    flags: 'DataFrameFlags'
    #: Padded length.
    pad_len: 'int'
    #: Frame payload.
    data: 'bytes'
    #: Padding octets, as captured (empty unless ``PADDED``).
    padding: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'DataFrameFlags', reserved: 'int', pad_len: 'int', sid: 'int', data: 'bytes', padding: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


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

    if TYPE_CHECKING:
        def __init__(self, END_STREAM: 'bool', END_HEADERS: 'bool', PADDED: 'bool', PRIORITY: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


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
    #: Padding octets, as captured (empty unless ``PADDED``).
    padding: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'HeadersFrameFlags', reserved: 'int', pad_len: 'int', sid: 'int', excl_dependency: 'bool', stream_dependency: 'int', weight: 'int', fragment: 'bytes', padding: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class PriorityFrame(HTTP):
    """Data model for HTTP/2 ``PRIORITY`` frame."""

    #: Flags.
    flags: 'Flags'
    #: Exclusive dependency.
    excl_dependency: 'bool'
    #: Stream dependency.
    stream_dependency: 'int'
    #: Weight.
    weight: 'int'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Flags', reserved: 'int', sid: 'int', excl_dependency: 'bool', stream_dependency: 'int', weight: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class RSTStreamFrame(HTTP):
    """Data model for HTTP/2 ``RST_STREAM`` frame."""

    #: Flags.
    flags: 'Flags'
    #: Error code.
    error: 'ErrorCode'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Flags', reserved: 'int', sid: 'int', error: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Settings(OrderedMultiDict['Setting', int]):
    """Settings of an HTTP/2 ``SETTINGS`` frame.

    An identifier may repeat, and the values apply in order, so the last one
    wins (:rfc:`9113#section-6.5`). Every entry is kept in wire order, as
    :meth:`getlist` and ``items(multi=True)`` show and the rebuild writes, but
    indexing, :meth:`get`, :meth:`values`, ``items()`` and :meth:`to_dict`
    answer with the *last* value of each identifier rather than the first.

    """

    def __getitem__(self, key: 'Setting') -> 'int':
        if key in self:
            return self.getlist(key)[-1]
        return super().__getitem__(key)

    def items(self, multi: 'bool' = False) -> 'Iterator[tuple[Setting, int]]':  # type: ignore[override]
        if multi:
            yield from super().items(multi=True)
            return
        for key, _ in super().items():
            yield key, self[key]


@info_final
class SettingsFrameFlags(Flags):
    """Data model for HTTP/2 ``SETTINGS`` frame flags."""

    #: ``ACK`` flag.
    ACK: 'bool'  # bit 0

    if TYPE_CHECKING:
        def __init__(self, ACK: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class SettingsFrame(HTTP):
    """Data model for HTTP/2 ``SETTINGS`` frame."""

    #: Flags.
    flags: 'SettingsFrameFlags'
    #: Settings.
    settings: 'Settings'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Flags', reserved: 'int', sid: 'int', settings: 'Settings') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class PushPromiseFrameFlags(Flags):
    """Data model for HTTP/2 ``PUSH_PROMISE`` frame flags."""

    #: ``END_HEADERS`` flag.
    END_HEADERS: 'bool'  # bit 2
    #: ``PADDED`` flag.
    PADDED: 'bool'       # bit 3

    if TYPE_CHECKING:
        def __init__(self, END_HEADERS: 'bool', PADDED: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class PushPromiseFrame(HTTP):
    """Data model for HTTP/2 ``PUSH_PROMISE`` frame."""

    #: Flags.
    flags: 'PushPromiseFrameFlags'
    #: Padded length.
    pad_len: 'int'
    #: Reserved bit of the promised stream ID.
    promised_reserved: 'int'
    #: Promised stream ID.
    promised_sid: 'int'
    #: Header block fragment.
    fragment: 'bytes'
    #: Padding octets, as captured (empty unless ``PADDED``).
    padding: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Flags', reserved: 'int', pad_len: 'int', sid: 'int', promised_reserved: 'int', promised_sid: 'int', fragment: 'bytes', padding: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class PingFrameFlags(Flags):
    """Data model for HTTP/2 ``PING`` frame flags."""

    #: ``ACK`` flag.
    ACK: 'bool'  # bit 0

    if TYPE_CHECKING:
        def __init__(self, ACK: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class PingFrame(HTTP):
    """Data model for HTTP/2 ``PING`` frame."""

    #: Flags.
    flags: 'PingFrameFlags'
    #: Opaque data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Flags', reserved: 'int', sid: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class GoawayFrame(HTTP):
    """Data model for HTTP/2 ``GOAWAY`` frame."""

    #: Flags.
    flags: 'Flags'
    #: Reserved bit of the last stream ID.
    last_reserved: 'int'
    #: Last stream ID.
    last_sid: 'int'
    #: Error code.
    error: 'ErrorCode'
    #: Additional debug data.
    debug_data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Flags', reserved: 'int', sid: 'int', last_reserved: 'int', last_sid: 'int', error: 'int', debug_data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class WindowUpdateFrame(HTTP):
    """Data model for HTTP/2 ``WINDOW_UPDATE`` frame."""

    #: Flags.
    flags: 'Flags'
    #: Reserved bit of the window size increment.
    increment_reserved: 'int'
    #: Window size increment.
    increment: 'int'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Flags', reserved: 'int', sid: 'int', increment_reserved: 'int', increment: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class ContinuationFrameFlags(Flags):
    """Data model for HTTP/2 ``CONTINUATION`` frame flags."""

    #: ``END_HEADERS`` flag.
    END_HEADERS: 'bool'  # bit 2

    if TYPE_CHECKING:
        def __init__(self, END_HEADERS: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class ContinuationFrame(HTTP):
    """Data model for HTTP/2 ``CONTINUATION`` frame."""

    #: Flags.
    flags: 'ContinuationFrameFlags'
    #: Header block fragment.
    fragment: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Frame', flags: 'Flags', reserved: 'int', sid: 'int', fragment: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin
