# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for HTTP/2 protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.application.httpv2.HTTP``, with no alias. The
   class is renamed :class:`~pcapkit.protocols.application.httpv2.schema.HTTPv2`,
   after its module (:issue:`2529`).

"""

import collections
import enum
from typing import TYPE_CHECKING, cast

from pcapkit.const.http.error_code import ErrorCode as Enum_ErrorCode
from pcapkit.const.http.frame import Frame as Enum_Frame
from pcapkit.const.http.setting import Setting as Enum_Setting
from pcapkit.corekit.enum import EnumLookup
from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField, SchemaField, SwitchField
from pcapkit.corekit.fields.numbers import EnumField, NumberField, UInt8Field, UInt32Field
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = [
    'HTTPv2',

    'FrameType',
    'UnassignedFrame', 'DataFrame', 'HeadersFrame', 'PriorityFrame',
    'RSTStreamFrame', 'SettingsFrame', 'PushPromiseFrame', 'PingFrame',
    'GoawayFrame', 'WindowUpdateFrame', 'ContinuationFrame',
]

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.protocol import ProtocolBase

if SPHINX_TYPE_CHECKING:  # pragma: no cover
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

        #: Reserved bit.
        reserved: int
        #: Stream identifier.
        sid: int

    class StreamDependency(TypedDict):
        """Stream dependency."""

        #: Exclusive flag.
        exclusive: int
        #: Stream dependency identifier.
        sid: int

    class WindowSize(TypedDict):
        """Window size increment."""

        #: Reserved bit.
        reserved: int
        #: Window size increment.
        incr: int


def http_frame_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`HTTPv2.frame` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
        :class:`~pcapkit.protocols.application.httpv2.schema.FrameType`
        instance.

    """
    type = cast('Enum_Frame', pkt['type'])
    schema = FrameType.registry[type]
    # Bounded by the declared Length, leaving the next frame for the payload,
    # and by the buffer, so ``HTTPv2.read`` rejects a Length nothing backs.
    return SchemaField(length=min(pkt['length'], pkt['__length__']), schema=schema)


@schema_final
class HTTPv2(Schema):
    """Header schema for HTTP/2 packet."""

    #: Length of the frame payload, the 9-octet header excluded.
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
        'reserved': (0, 1),
        'sid': (1, 31),
    })
    #: Frame payload.
    frame: 'FrameType' = SwitchField(
        selector=http_frame_selector,
    )
    #: Octets after the frame, e.g. the next frame.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, length: 'int', type: 'Enum_Frame', flags: 'FrameFlags', stream: 'StreamID', frame: 'FrameType | bytes', payload: 'bytes | ProtocolBase | Schema') -> 'None': ...


class FrameType(EnumSchema[Enum_Frame]):
    """Header schema for HTTP/2 frame payload."""

    if TYPE_CHECKING:
        # Qualified rather than ``'Flags'``: documentation tools evaluate a class
        # annotation against the module's globals, not the class body, so the
        # bare nested name cannot be found there (#1857).
        __flags__: 'FrameType.Flags'

    __enum__ = collections.defaultdict(lambda: UnassignedFrame)

    class Flags(EnumLookup, enum.IntFlag):
        """Flags enumeration for HTTP/2 frames.

        Built on :class:`~pcapkit.corekit.enum.EnumLookup`, the lookup contract
        shared by every non-registry enumeration. The concrete per-frame
        subclasses below each declare ``class Flags(FrameType.Flags):`` with no
        base list of their own, so they inherit :class:`~pcapkit.corekit.enum.EnumLookup`
        transitively rather than needing it repeated.

        """

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        # Seeded with ``Flags(0)``, as the construct path is, so a frame with no
        # flag set still reports ``__flags__`` as ``Flags``: an ``in`` test on a
        # plain ``int`` raises TypeError. The memberless
        # ``FrameType.Flags``, which Python 3.11+ refuses to call, keeps the
        # plain ``int`` for the frame schemas that inherit it unchanged.
        flags = self.Flags(0) if self.Flags.__members__ else 0
        for key, val in filter(lambda kv: kv[0].startswith('BIT_'),
                               self.Flags.__members__.items()):
            name = key.lower()
            if packet['flags'][name]:
                flags |= val

        # Undefined bits are kept as pseudo-members: a receiver ignores them
        # (RFC 9113, section 4.1), but a rebuild must not erase them.
        raw = sum(packet['flags'][f'bit_{bit}'] << bit for bit in range(8))
        self.__flags__ = flags | (raw & ~int(flags))
        return self


@schema_final
class UnassignedFrame(FrameType):
    """Header schema for unassigned HTTP/2 frame payload."""

    #: Frame payload.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class DataFrame(FrameType, code=Enum_Frame.DATA):
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
    # NOTE: Parenthesised, or ``a - b if t else 0`` reads as ``(a - b) if t else 0`` and an
    # unpadded frame reads no data; the guard leaves ``pad_len`` (``NO_VALUE``) unread.
    #: Data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'] - (
        pkt['pad_len'] if pkt['flags']['bit_3'] else 0
    ))
    #: Padding.
    padding: 'bytes' = ConditionalField(
        PaddingField(length=lambda pkt: pkt['pad_len']),
        lambda pkt: pkt['flags']['bit_3'],  # PADDED
    )

    if TYPE_CHECKING:
        def __init__(self, pad_len: 'Optional[int]', data: 'bytes', padding: 'Optional[bytes]') -> 'None': ...


@schema_final
class HeadersFrame(FrameType, code=Enum_Frame.HEADERS):
    """Header schema for HTTP/2 ``HEADERS`` frames."""

    class Flags(FrameType.Flags):
        """Flags enumeration for HTTP/2 ``HEADERS`` frames."""

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
    # NOTE: Parenthesised as in ``DataFrame.data``.
    #: Header block fragment.
    fragment: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'] - (
        pkt['pad_len'] if pkt['flags']['bit_3'] else 0
    ))
    #: Padding.
    padding: 'bytes' = ConditionalField(
        PaddingField(length=lambda pkt: pkt['pad_len']),
        lambda pkt: pkt['flags']['bit_3'],  # PADDED
    )

    if TYPE_CHECKING:
        def __init__(self, pad_len: 'Optional[int]', stream_dep: 'Optional[StreamDependency]', weight: 'Optional[int]', fragment: 'bytes', padding: 'Optional[bytes]') -> 'None': ...


@schema_final
class PriorityFrame(FrameType, code=Enum_Frame.PRIORITY):
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
class RSTStreamFrame(FrameType, code=Enum_Frame.RST_STREAM):
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
class SettingsFrame(FrameType, code=Enum_Frame.SETTINGS):
    """Header schema for HTTP/2 ``SETTINGS`` frames."""

    class Flags(FrameType.Flags):
        """Flags enumeration for HTTP/2 ``SETTINGS`` frames."""

        ACK = BIT_0 = 0x1

    #: Settings.
    settings: 'list[SettingPair]' = ListField(
        length=lambda pkt: pkt['__length__'],
        item_type=SchemaField(length=6, schema=SettingPair),
    )

    if TYPE_CHECKING:
        def __init__(self, settings: 'list[SettingPair] | bytes') -> 'None': ...


@schema_final
class PushPromiseFrame(FrameType, code=Enum_Frame.PUSH_PROMISE):
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
        'reserved': (0, 1),
        'sid': (1, 31),
    })
    # NOTE: Parenthesised as in ``DataFrame.data``.
    #: Header block fragment.
    fragment: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'] - (
        pkt['pad_len'] if pkt['flags']['bit_3'] else 0
    ))
    #: Padding.
    padding: 'bytes' = ConditionalField(
        PaddingField(length=lambda pkt: pkt['pad_len']),
        lambda pkt: pkt['flags']['bit_3'],  # PADDED
    )

    if TYPE_CHECKING:
        def __init__(self, pad_len: 'Optional[int]', stream: 'StreamID', fragment: 'bytes', padding: 'Optional[bytes]') -> 'None': ...


@schema_final
class PingFrame(FrameType, code=Enum_Frame.PING):
    """Header schema for HTTP/2 ``PING`` frames."""

    class Flags(FrameType.Flags):
        """Flags enumeration for HTTP/2 ``PING`` frames."""

        ACK = BIT_0 = 0x1

    #: Opaque data.
    data: 'bytes' = BytesField(length=8)

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class GoawayFrame(FrameType, code=Enum_Frame.GOAWAY):
    """Header schema for HTTP/2 ``GOAWAY`` frames."""

    #: Last stream ID.
    stream: 'StreamID' = BitField(length=4, namespace={
        'reserved': (0, 1),
        'sid': (1, 31),
    })
    #: Error code.
    error: 'Enum_ErrorCode' = EnumField(length=4, namespace=Enum_ErrorCode)
    #: Additional debug data.
    debug: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, stream: 'StreamID', error: 'Enum_ErrorCode', debug: 'bytes') -> 'None': ...


@schema_final
class WindowUpdateFrame(FrameType, code=Enum_Frame.WINDOW_UPDATE):
    """Header schema for HTTP/2 ``WINDOW_UPDATE`` frames."""

    #: Window size increment.
    size: 'WindowSize' = BitField(length=4, namespace={
        'reserved': (0, 1),
        'incr': (1, 31),
    })

    if TYPE_CHECKING:
        def __init__(self, size: 'WindowSize') -> 'None': ...


@schema_final
class ContinuationFrame(FrameType, code=Enum_Frame.CONTINUATION):
    """Header schema for HTTP/2 ``CONTINUATION`` frames."""

    class Flags(FrameType.Flags):
        """Flags enumeration for HTTP/2 ``CONTINUATION`` frames."""

        END_HEADERS = BIT_2 = 0x4

    #: Header block fragment.
    fragment: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, fragment: 'bytes') -> 'None': ...
