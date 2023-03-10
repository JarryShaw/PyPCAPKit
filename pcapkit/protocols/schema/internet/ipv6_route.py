# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for IPv6 Routing Header"""

from typing import TYPE_CHECKING

from pcapkit.const.ipv6.routing import Routing as Enum_Routing
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.ipaddress import IPv6Field
from pcapkit.corekit.fields.misc import ListField, PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema

__all__ = [
    'IPv6_Route',

    'RoutingType',
    'UnknownType', 'SourceRoute', 'Type2', 'RPL',
]

if TYPE_CHECKING:
    from ipaddress import IPv6Address

    from typing_extensions import TypedDict

    from pcapkit.protocols.protocol import Protocol

    class PadInfo(TypedDict):
        """Padding length and reserved."""

        pad_len: int


class IPv6_Route(Schema):
    """Header schema for IPv6-Route packet."""

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Header extension length.
    length: 'int' = UInt8Field()
    #: Routing type.
    type: 'Enum_Routing' = EnumField(length=1, namespace=Enum_Routing)
    #: Segments left.
    seg_left: 'int' = UInt8Field()
    #: Routing data.
    data: 'RoutingType' = PayloadField(length=lambda pkt: pkt['length'] * 8 + 4)
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType', length: 'int', type: 'Enum_Routing',
                     seg_left: 'int', data: 'bytes | RoutingType', payload: 'Protocol | Schema | bytes') -> 'None': ...


class RoutingType(Schema):
    """Header schema for IPv6-Route type-specific routing data."""


class UnknownType(RoutingType):
    """Header schema for IPv6-Route unknown type routing data."""

    #: Type-specific data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] * 8 + 4)

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


class SourceRoute(RoutingType):
    """Header schema for IPv6-Route source route routing data."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=4)
    #: Addresses.
    ip: 'list[IPv6Address]' = ListField(
        length=lambda pkt: pkt['length'] * 8,
        item_type=IPv6Field(),
    )

    if TYPE_CHECKING:
        def __init__(self, ip: 'list[IPv6Address | str | int | bytes]') -> 'None': ...


class Type2(RoutingType):
    """Header schema for IPv6-Route type 2 routing data."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=4)
    #: Addresses.
    ip: 'IPv6Address' = IPv6Field()

    if TYPE_CHECKING:
        def __init__(self, ip: 'IPv6Address | str | int | bytes') -> 'None': ...


class RPL(RoutingType):
    """Header schema for IPv6-Route RPL routing data."""

    #: CmprI.
    cmpr_i: 'int' = UInt8Field()
    #: CmprE.
    cmpr_e: 'int' = UInt8Field()
    #: Padding length and reserved.
    pad: 'PadInfo' = BitField(length=3, namespace={
        'pad_len': (0, 4),
    })
    #: Addresses.
    ip: 'list[IPv6Address | bytes]' = ListField(
        length=lambda pkt: pkt['length'] * 8 - pkt['pad']['pad_len'],
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: pkt['pad']['pad_len'])

    if TYPE_CHECKING:
        def __init__(self, cmpr_i: 'int', cmpr_e: 'int', pad: 'PadInfo',
                     ip: 'list[bytes]') -> 'None': ...
