# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for HTTP/2 protocol"""

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
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final
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
    """Selector function for :attr:`HTTP.frame` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
        :class:`~pcapkit.protocols.schema.application.httpv2.FrameType`
        instance.

    """
    type = cast('Enum_Frame', pkt['type'])
    schema = FrameType.registry[type]
    # The frame payload is bounded by the declared Length, so anything after
    # it -- typically the next frame -- is left for :attr:`HTTP.payload`. It is
    # bounded by the buffer as well, so that a Length the buffer cannot back
    # reaches :meth:`HTTP.read <pcapkit.protocols.application.httpv2.HTTP.read>`,
    # which rejects it with :exc:`~pcapkit.utilities.exceptions.ProtocolError`.
    return SchemaField(length=min(pkt['length'], pkt['__length__']), schema=schema)


@schema_final
class HTTP(Schema):
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
        __flags__: 'Flags'

    __enum__ = collections.defaultdict(lambda: UnassignedFrame)

    class Flags(EnumLookup, enum.IntFlag):
        """Flags enumeration for HTTP/2 frames.

        Built on :class:`~pcapkit.corekit.enum.EnumLookup`, the lookup contract
        shared by every non-registry enumeration. The six concrete per-frame
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
        # Seed the accumulator with the frame's own ``Flags`` rather than a bare
        # ``0``, so that a frame with no bit set still reports ``__flags__`` as
        # the ``Flags`` both this schema and :class:`~pcapkit.protocols.data.\
        # application.httpv2.Flags` declare it to be. ``|=`` promotes a plain
        # ``0`` only as a side effect, so without this a flags octet of ``0x00``
        # -- routine in HTTP/2, not an edge case -- leaves an ``int`` behind and
        # a membership test against it raises :exc:`TypeError` rather than
        # answering. This mirrors the construct path, which seeds
        # ``Flags(0)`` at every one of its six sites.
        #
        # ``FrameType.Flags`` itself declares no members, and from Python 3.11
        # the enum rewrite makes a memberless :class:`enum.Flag` subclass refuse
        # ``Flags(0)`` outright with ``TypeError: <flag 'Flags'> has no members
        # defined`` (3.10 and earlier hand back a pseudo-member instead), so
        # the five frame schemas that inherit it unchanged -- ``UnassignedFrame``,
        # ``PriorityFrame``, ``RSTStreamFrame``, ``GoawayFrame`` and
        # ``WindowUpdateFrame`` -- keep the plain ``int``, which is what their
        # data objects' bare ``Flags`` carries as ``__value__``.
        flags = self.Flags(0) if self.Flags.__members__ else 0
        for key, val in filter(lambda kv: kv[0].startswith('BIT_'),
                               self.Flags.__members__.items()):
            name = key.lower()
            if packet['flags'][name]:
                flags |= val

        # Bits the frame type leaves undefined are kept as well: a receiver
        # ignores them (:rfc:`9113#section-4.1`), but a rebuild must not erase
        # them. ``Flags`` keeps such bits as pseudo-members.
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
    #: Data.
    #
    # NOTE: the conditional subtracts the padding length, it does not *replace*
    # the whole expression. A conditional expression binds looser than ``-``, so
    # writing ``pkt['__length__'] - pkt['pad_len'] if <test> else 0`` groups as
    # ``(pkt['__length__'] - pkt['pad_len']) if <test> else 0`` and hands back ``0``
    # -- "read no payload at all" -- for every frame without the ``PADDED``
    # flag. ``__length__`` is the *remaining* declared length at this field, so
    # the unpadded arm wants ``__length__`` itself, which is what subtracting a
    # zero padding length gives. Padding is rare in HTTP/2, so that arm would be
    # the common one: an unpadded ``DATA`` frame would parse with ``data`` as
    # ``b''`` and nothing would raise or warn. The parentheses also keep
    # ``pkt['pad_len']`` from being read at all when ``PADDED`` is clear, where
    # the :class:`~pcapkit.corekit.fields.misc.ConditionalField` above has left
    # it as :data:`~pcapkit.corekit.fields.field.NO_VALUE`.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'] - (
        pkt['pad_len'] if pkt['flags']['bit_3'] else 0
    ))
    #: Padding.
    padding: 'bytes' = ConditionalField(
        PaddingField(length=lambda pkt: pkt['pad_len']),
        lambda pkt: pkt['flags']['bit_3'],  # PADDED
    )

    if TYPE_CHECKING:
        def __init__(self, pad_len: 'Optional[int]', data: 'bytes') -> 'None': ...


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
    #: Header block fragment.
    #
    # NOTE: the conditional subtracts the padding length rather than replacing
    # the whole expression -- see :attr:`DataFrame.data` for why the outer
    # parentheses are load-bearing. Without them an unpadded ``HEADERS`` frame
    # would read its header block fragment as ``b''``.
    fragment: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'] - (
        pkt['pad_len'] if pkt['flags']['bit_3'] else 0
    ))
    #: Padding.
    padding: 'bytes' = ConditionalField(
        PaddingField(length=lambda pkt: pkt['pad_len']),
        lambda pkt: pkt['flags']['bit_3'],  # PADDED
    )

    if TYPE_CHECKING:
        def __init__(self, pad_len: 'Optional[int]', stream_dep: 'Optional[StreamDependency]', weight: 'Optional[int]', fragment: 'bytes') -> 'None': ...


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
    #: Header block fragment.
    #
    # NOTE: the conditional subtracts the padding length rather than replacing
    # the whole expression -- see :attr:`DataFrame.data` for why the outer
    # parentheses are load-bearing. Without them an unpadded ``PUSH_PROMISE``
    # frame would read its header block fragment as ``b''``.
    fragment: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'] - (
        pkt['pad_len'] if pkt['flags']['bit_3'] else 0
    ))
    #: Padding.
    padding: 'bytes' = ConditionalField(
        PaddingField(length=lambda pkt: pkt['pad_len']),
        lambda pkt: pkt['flags']['bit_3'],  # PADDED
    )

    if TYPE_CHECKING:
        def __init__(self, pad_len: 'Optional[int]', stream: 'StreamID', fragment: 'bytes') -> 'None': ...


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
