# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for ICMPv6 protocol"""

from typing import TYPE_CHECKING, cast

from pcapkit.const.icmpv6.type import Type as Enum_Type
from pcapkit.corekit.fields.misc import SchemaField, SwitchField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField, PaddingField
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final

__all__ = [
    'ICMPv6',

    'ICMPv6Type', 'Unknown', 'DestinationUnreachable', 'PacketTooBig', 'TimeExceeded',
    'ParameterProblem', 'Echo',
]

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.corekit.fields.field import FieldBase as Field


def icmpv6_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`ICMPv6.data` field.

    Args:
        pkt: Packet data.

    Returns:
        A :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
        :class:`~pcapkit.protocols.schema.internet.icmpv6.ICMPv6Type` instance
        based on :attr:`ICMPv6.type <pcapkit.protocols.schema.internet.icmpv6.ICMPv6.type>`.

    """
    type = cast('Enum_Type', pkt['type'])
    schema = ICMPv6Type.registry[type]
    # NOTE: ``type``, ``code`` and ``checksum`` have already been deducted
    # from ``__length__``, so it is exactly the message body length.
    return SchemaField(length=cast('int', pkt['__length__']), schema=schema)


@schema_final
class ICMPv6(Schema):
    """Header schema for ICMPv6 packet."""

    #: ICMPv6 type.
    type: 'Enum_Type' = EnumField(length=1, namespace=Enum_Type)
    #: ICMPv6 code.
    code: 'int' = UInt8Field()
    #: Checksum.
    checksum: 'bytes' = BytesField(length=2)
    #: Message body, selected by :attr:`type`.
    data: 'ICMPv6Type' = SwitchField(selector=icmpv6_data_selector)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes',
                     data: 'bytes | ICMPv6Type') -> 'None': ...


class ICMPv6Type(EnumSchema[Enum_Type]):
    """Header schema for ICMPv6 type-specific message body."""

    __default__ = lambda: Unknown


@schema_final
class Unknown(ICMPv6Type):
    """Header schema for ICMPv6 message of unknown type."""

    #: Message body.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class DestinationUnreachable(ICMPv6Type, code=Enum_Type.Destination_Unreachable):
    """Header schema for ICMPv6 Destination Unreachable message."""

    #: Unused.
    unused: 'bytes' = PaddingField(length=4)
    #: As much of the invoking packet as fits the minimum IPv6 MTU.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, unused: 'bytes', data: 'bytes') -> 'None': ...


@schema_final
class PacketTooBig(ICMPv6Type, code=Enum_Type.Packet_Too_Big):
    """Header schema for ICMPv6 Packet Too Big message."""

    #: MTU of the link that could not forward the invoking packet.
    mtu: 'int' = UInt32Field()
    #: As much of the invoking packet as fits the minimum IPv6 MTU.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, mtu: 'int', data: 'bytes') -> 'None': ...


@schema_final
class TimeExceeded(ICMPv6Type, code=Enum_Type.Time_Exceeded):
    """Header schema for ICMPv6 Time Exceeded message."""

    #: Unused.
    unused: 'bytes' = PaddingField(length=4)
    #: As much of the invoking packet as fits the minimum IPv6 MTU.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, unused: 'bytes', data: 'bytes') -> 'None': ...


@schema_final
class ParameterProblem(ICMPv6Type, code=Enum_Type.Parameter_Problem):
    """Header schema for ICMPv6 Parameter Problem message."""

    #: Pointer.
    pointer: 'int' = UInt32Field()
    #: As much of the invoking packet as fits the minimum IPv6 MTU.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, pointer: 'int', data: 'bytes') -> 'None': ...


@schema_final
class Echo(ICMPv6Type, code=[Enum_Type.Echo_Request, Enum_Type.Echo_Reply]):
    """Header schema for ICMPv6 Echo Request/Reply message."""

    #: Identifier.
    id: 'int' = UInt16Field()
    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, id: 'int', seq: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=redefined-builtin
