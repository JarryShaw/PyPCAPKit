# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for HTTP/2 protocol"""

import enum
from typing import TYPE_CHECKING, cast

from pcapkit.const.http.error_code import ErrorCode as Enum_ErrorCode
from pcapkit.const.http.frame import Frame as Enum_Frame
from pcapkit.const.http.setting import Setting as Enum_Setting
from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.misc import ConditionalField, SchemaField, SwitchField
from pcapkit.corekit.fields.numbers import EnumField, NumberField, UInt8Field, UInt32Field
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = [
    'HTTP',

    'FrameType',
    'UnassignedFrame', 'DataFrame', 'HeadersFrame', 'PriorityFrame',
    'RSTStreamFrame', 'SettingsFrame', 'PushPromiseFrame', 'PingFrame',
    'GoawayFrame', 'WindowUpdateFrame', 'ContinuationFrame',
]

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.corekit.fields.field import _Field as Field

if SPHINX_TYPE_CHECKING:
    from typing_extensions import TypedDict

    class FrameFlags(TypedDict):
        """HTTP frame specific flags."""

        bit_7: int
        bit_6: int
        bit_5: int
        bit_4: int
        bit_3: int
        bit_2: int
        bit_1: int
        bit_0: int

    class StreamID(TypedDict):
        """Stream identifier."""

        #: Steam identifier.
        sid: int

    class StreamDependency(TypedDict):
        """Stream dependency."""

        #: Exclusive flag.
        exclusive: int
        #: Stream dependency identifier.
        sid: int

    class WindowSize(TypedDict):
        """Window size increment."""

        #: Window size increment.
        incr: int


def http_frame_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`HTTP.frame` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
        :class:`~pcapkit.protocols.schema.application.httpv2.FrameType`
        instance.

    """
    type = cast('Enum_Frame', pkt['type'])
    if type == Enum_Frame.DATA:
        return SchemaField(length=pkt['__length__'], schema=DataFrame)
    if type == Enum_Frame.HEADERS:
        return SchemaField(length=pkt['__length__'], schema=HeadersFrame)
    if type == Enum_Frame.PRIORITY:
        return SchemaField(length=pkt['__length__'], schema=PriorityFrame)
    if type == Enum_Frame.RST_STREAM:
        return SchemaField(length=pkt['__length__'], schema=RSTStreamFrame)
    if type == Enum_Frame.SETTINGS:
        return SchemaField(length=pkt['__length__'], schema=SettingsFrame)
    if type == Enum_Frame.PUSH_PROMISE:
        return SchemaField(length=pkt['__length__'], schema=PushPromiseFrame)
    if type == Enum_Frame.PING:
        return SchemaField(length=pkt['__length__'], schema=PingFrame)
    if type == Enum_Frame.GOAWAY:
        return SchemaField(length=pkt['__length__'], schema=GoawayFrame)
    if type == Enum_Frame.WINDOW_UPDATE:
        return SchemaField(length=pkt['__length__'], schema=WindowUpdateFrame)
    if type == Enum_Frame.CONTINUATION:
        return SchemaField(length=pkt['__length__'], schema=ContinuationFrame)
    return SchemaField(length=pkt['__length__'], schema=UnassignedFrame)


@schema_final
class HTTP(Schema):
    """Header schema for HTTP/2 packet."""

    #: Length.
    length: 'int' = NumberField(length=3, signed=False)
    #: Frame type.
    type: 'Enum_Frame' = EnumField(length=1, namespace=Enum_Frame)
    #: Frame specific flags.
    flags: 'FrameFlags' = BitField(length=1, namespace={
        'bit_7': (0, 1),
        'bit_6': (1, 1),
        'bit_5': (2, 1),
        'bit_4': (3, 1),
        'bit_3': (4, 1),
        'bit_2': (5, 1),
        'bit_1': (6, 1),
        'bit_0': (7, 1),
    })
    #: Stream identifier.
    stream: 'StreamID' = BitField(length=4, namespace={
        'sid': (1, 31),
    })
    #: Frame payload.
    frame: 'FrameType' = SwitchField(
        selector=http_frame_selector,
    )

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Enum_Frame', flags: 'FrameFlags', stream: 'StreamID', frame: 'FrameType | bytes') -> 'None': ...


class FrameType(Schema):
    """Header schema for HTTP/2 frame payload."""

    if TYPE_CHECKING:
        __flags__: 'Flags'

    class Flags(enum.IntFlag):
        """Flags enumeration for HTTP/2 frames."""

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            schema: parsed schema
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        flags = 0
        for key, val in filter(lambda kv: kv[0].startswith('BIT_'),
                               self.Flags.__members__.items()):
            name = key.lower()
            if packet['flags'][name]:
                flags |= val

        self.__flags__ = flags
        return self


@schema_final
class UnassignedFrame(FrameType):
    """Header schema for unassigned HTTP/2 frame payload."""

    #: Frame payload.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class DataFrame(FrameType):
    """Header schema for HTTP/2 ``DATA`` frames."""

    class Flags(FrameType.Flags):
        """Flags enumeration for HTTP/2 ``DATA`` frames."""

        END_STREAM = BIT_0 = 0x1
        PADDED     = BIT_3 = 0x8

    #: Padding length.
    pad_len: 'int' = ConditionalField(
        UInt8Field(),
        lambda pkt: pkt['flags']['bit_3'],  # PADDED
    )
    #: Data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'] - pkt['pad_len'] if pkt['flags']['bit_3'] else 0)
    #: Padding.
    padding: 'bytes' = ConditionalField(
        PaddingField(length=lambda pkt: pkt['pad_len']),
        lambda pkt: pkt['flags']['bit_3'],  # PADDED
    )

    if TYPE_CHECKING:
        def __init__(self, pad_len: 'Optional[int]', data: 'bytes') -> 'None': ...


@schema_final
class HeadersFrame(FrameType):
    """Header schema for HTTP/2 ``HEADERS`` frames."""

    class Flags(FrameType.Flags):
        """Flags enumeration for HTTP/2 ``DATA`` frames."""

        END_STREAM  = BIT_0 = 0x1
        END_HEADERS = BIT_2 = 0x4
        PADDED      = BIT_3 = 0x8
        PRIORITY    = BIT_5 = 0x20

    #: Padding length.
    pad_len: 'int' = ConditionalField(
        UInt8Field(),
        lambda pkt: pkt['flags']['bit_3'],  # PADDED
    )
    #: Stream dependency.
    stream_dep: 'StreamDependency' = ConditionalField(
        BitField(length=4, namespace={
            'exclusive': (0, 1),
            'sid': (1, 31),
        }),
        lambda pkt: pkt['flags']['bit_5'],  # PRIORITY
    )
    #: Weight.
    weight: 'int' = ConditionalField(
        UInt8Field(),
        lambda pkt: pkt['flags']['bit_5'],  # PRIORITY
    )
    #: Header block fragment.
    fragment: 'bytes' = BytesField(length=lambda pkt: (
        pkt['__length__'] - pkt['pad_len'] if pkt['flags']['bit_3'] else 0
    ))
    #: Padding.
    padding: 'bytes' = ConditionalField(
        PaddingField(length=lambda pkt: pkt['pad_len']),
        lambda pkt: pkt['flags']['bit_3'],  # PADDED
    )

    if TYPE_CHECKING:
        def __init__(self, pad_len: 'Optional[int]', stream_dep: 'Optional[StreamDependency]', weight: 'Optional[int]', fragment: 'bytes') -> 'None': ...


@schema_final
class PriorityFrame(FrameType):
    """Header schema for HTTP/2 ``PRIORITY`` frames."""

    #: Stream dependency (exclusive, stream ID).
    stream: 'StreamDependency' = BitField(length=4, namespace={
        'exclusive': (0, 1),
        'sid': (1, 31),
    })
    #: Weight.
    weight: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, stream: 'StreamDependency', weight: 'int') -> 'None': ...


@schema_final
class RSTStreamFrame(FrameType):
    """Header schema for HTTP/2 ``RST_STREAM`` frames."""

    #: Error code.
    error: 'Enum_ErrorCode' = EnumField(length=4, namespace=Enum_ErrorCode)

    if TYPE_CHECKING:
        def __init__(self, error: 'Enum_ErrorCode') -> 'None': ...


@schema_final
class SettingPair(Schema):
    """Header schema for HTTP/2 ``SETTINGS`` frame setting pairs."""

    #: Identifier.
    id: 'Enum_Setting' = EnumField(length=2, namespace=Enum_Setting)
    #: Value.
    value: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, id: 'Enum_Setting', value: 'int') -> 'None': ...


@schema_final
class SettingsFrame(FrameType):
    """Header schema for HTTP/2 ``SETTINGS`` frames."""

    class Flags(FrameType.Flags):
        """Flags enumeration for HTTP/2 ``SETTINGS`` frames."""

        ACK = BIT_0 = 0x1

    #: Settings.
    settings: 'list[SettingPair]' = ListField(
        length=lambda pkt: pkt['__length__'],
        item_type=SettingPair,  # type: ignore[arg-type]
    )

    if TYPE_CHECKING:
        def __init__(self, settings: 'list[SettingPair] | bytes') -> 'None': ...


@schema_final
class PushPromiseFrame(FrameType):
    """Header schema for HTTP/2 ``PUSH_PROMISE`` frames."""

    class Flags(FrameType.Flags):
        """Flags enumeration for HTTP/2 ``PUSH_PROMISE`` frames."""

        END_HEADERS = BIT_2 = 0x4
        PADDED      = BIT_3 = 0x8

    #: Padding length.
    pad_len: 'int' = ConditionalField(
        UInt8Field(),
        lambda pkt: pkt['flags']['bit_3'],  # PADDED
    )
    #: Promised stream ID.
    stream: 'StreamID' = BitField(length=4, namespace={
        'sid': (1, 31),
    })
    #: Header block fragment.
    fragment: 'bytes' = BytesField(length=lambda pkt: (
        pkt['__length__'] - pkt['pad_len'] if pkt['flags']['bit_3'] else 0
    ))
    #: Padding.
    padding: 'bytes' = ConditionalField(
        PaddingField(length=lambda pkt: pkt['pad_len']),
        lambda pkt: pkt['flags']['bit_3'],  # PADDED
    )

    if TYPE_CHECKING:
        def __init__(self, pad_len: 'Optional[int]', stream: 'StreamID', fragment: 'bytes') -> 'None': ...


@schema_final
class PingFrame(FrameType):
    """Header schema for HTTP/2 ``PING`` frames."""

    class Flags(FrameType.Flags):
        """Flags enumeration for HTTP/2 ``PING`` frames."""

        ACK = BIT_0 = 0x1

    #: Opaque data.
    data: 'bytes' = BytesField(length=8)

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class GoawayFrame(FrameType):
    """Header schema for HTTP/2 ``GOAWAY`` frames."""

    #: Last stream ID.
    stream: 'StreamID' = BitField(length=4, namespace={
        'sid': (1, 31),
    })
    #: Error code.
    error: 'Enum_ErrorCode' = EnumField(length=4, namespace=Enum_ErrorCode)
    #: Additional debug data.
    debug: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, stream: 'StreamID', error: 'Enum_ErrorCode', debug: 'bytes') -> 'None': ...


@schema_final
class WindowUpdateFrame(FrameType):
    """Header schema for HTTP/2 ``WINDOW_UPDATE`` frames."""

    #: Window size increment.
    size: 'WindowSize' = BitField(length=4, namespace={
        'incr': (1, 31),
    })

    if TYPE_CHECKING:
        def __init__(self, size: 'WindowSize') -> 'None': ...


@schema_final
class ContinuationFrame(FrameType):
    """Header schema for HTTP/2 ``CONTINUATION`` frames."""

    class Flags(FrameType.Flags):
        """Flags enumeration for HTTP/2 ``CONTINUATION`` frames."""

        END_HEADERS = BIT_2 = 0x4

    #: Header block fragment.
    fragment: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, fragment: 'bytes') -> 'None': ...
