# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for ICMP protocol"""

from typing import TYPE_CHECKING, cast

from pcapkit.const.icmp.type import Type as Enum_Type
from pcapkit.corekit.fields.misc import SchemaField, SwitchField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BytesField, PaddingField
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final

__all__ = [
    'ICMPv4',

    'ICMPv4Type', 'Unknown', 'Echo', 'DestinationUnreachable', 'TimeExceeded', 'ParameterProblem',
]

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.corekit.fields.field import FieldBase as Field


def icmpv4_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`ICMPv4.data` field.

    Args:
        pkt: Packet data.

    Returns:
        A :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
        :class:`~pcapkit.protocols.schema.internet.icmpv4.ICMPv4Type` instance
        based on :attr:`ICMPv4.type <pcapkit.protocols.schema.internet.icmpv4.ICMPv4.type>`.

    """
    type = cast('Enum_Type', pkt['type'])
    schema = ICMPv4Type.registry[type]
    # NOTE: ``type``, ``code`` and ``checksum`` have already been deducted
    # from ``__length__``, so it is exactly the message body length.
    return SchemaField(length=cast('int', pkt['__length__']), schema=schema)


@schema_final
class ICMPv4(Schema):
    """Header schema for ICMP packet."""

    #: ICMP type.
    type: 'Enum_Type' = EnumField(length=1, namespace=Enum_Type)
    #: ICMP code.
    code: 'int' = UInt8Field()
    #: Checksum.
    checksum: 'bytes' = BytesField(length=2)
    #: Message body, selected by :attr:`type`.
    data: 'ICMPv4Type' = SwitchField(selector=icmpv4_data_selector)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes',
                     data: 'bytes | ICMPv4Type') -> 'None': ...


class ICMPv4Type(EnumSchema[Enum_Type]):
    """Header schema for ICMP type-specific message body."""

    __default__ = lambda: Unknown


@schema_final
class Unknown(ICMPv4Type):
    """Header schema for ICMP message of unknown type."""

    #: Message body.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class Echo(ICMPv4Type, code=[Enum_Type.Echo, Enum_Type.Echo_Reply]):
    """Header schema for ICMP Echo Request/Reply message."""

    #: Identifier.
    id: 'int' = UInt16Field()
    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, id: 'int', seq: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=redefined-builtin


@schema_final
class DestinationUnreachable(ICMPv4Type, code=Enum_Type.Destination_Unreachable):
    """Header schema for ICMP Destination Unreachable message."""

    #: Unused.
    unused: 'bytes' = PaddingField(length=4)
    #: Internet header plus the first eight octets of the original
    #: datagram's payload.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, unused: 'bytes', data: 'bytes') -> 'None': ...


@schema_final
class TimeExceeded(ICMPv4Type, code=Enum_Type.Time_Exceeded):
    """Header schema for ICMP Time Exceeded message."""

    #: Unused.
    unused: 'bytes' = PaddingField(length=4)
    #: Internet header plus the first eight octets of the original
    #: datagram's payload.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, unused: 'bytes', data: 'bytes') -> 'None': ...


@schema_final
class ParameterProblem(ICMPv4Type, code=Enum_Type.Parameter_Problem):
    """Header schema for ICMP Parameter Problem message."""

    #: Pointer.
    pointer: 'int' = UInt8Field()
    #: Unused.
    unused: 'bytes' = PaddingField(length=3)
    #: Internet header plus the first eight octets of the original
    #: datagram's payload.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, pointer: 'int', unused: 'bytes', data: 'bytes') -> 'None': ...
