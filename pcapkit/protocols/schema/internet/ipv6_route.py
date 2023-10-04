# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for IPv6 Routing Header"""

import ipaddress
from typing import TYPE_CHECKING, cast

from pcapkit.const.ipv6.routing import Routing as Enum_Routing
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.ipaddress import IPv6AddressField
from pcapkit.corekit.fields.misc import PayloadField, SchemaField, SwitchField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = [
    'IPv6_Route',

    'RoutingType',
    'UnknownType', 'SourceRoute', 'Type2', 'RPL',
]

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import Any, Optional

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

if SPHINX_TYPE_CHECKING:
    from typing_extensions import TypedDict

    class PadInfo(TypedDict):
        """Padding length and reserved."""

        pad_len: int


def ipv6_route_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`IPv6_Route.data` field.

    Args:
        pkt: Packet data.

    Returns:
        A :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
        :class:`~pcapkit.protocols.schema.internet.ipv6_route.RoutingType`
        instance based on :attr:`IPv6_Route.type <pcapkit.protocols.schema.internet.ipv6_route.IPv6_Route.type>`.

    """
    type = cast('Enum_Routing', pkt['type'])
    schema = RoutingType.registry[type]
    return SchemaField(length=pkt['length'] * 8 - 4, schema=schema)


@schema_final
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
    data: 'RoutingType' = SwitchField(
        selector=ipv6_route_data_selector,
    )
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType', length: 'int', type: 'Enum_Routing',
                     seg_left: 'int', data: 'bytes | RoutingType', payload: 'Protocol | Schema | bytes') -> 'None': ...


class RoutingType(EnumSchema[Enum_Routing]):
    """Header schema for IPv6-Route type-specific routing data."""

    __default__ = lambda: UnknownType


@schema_final
class UnknownType(RoutingType):
    """Header schema for IPv6-Route unknown type routing data."""

    #: Type-specific data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class SourceRoute(RoutingType, code=Enum_Routing.Source_Route):
    """Header schema for IPv6-Route source route routing data."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=4)
    #: Addresses.
    ip: 'list[IPv6Address]' = ListField(
        length=lambda pkt: pkt['__length__'],
        item_type=IPv6AddressField(),
    )

    if TYPE_CHECKING:
        def __init__(self, ip: 'list[IPv6Address | str | int | bytes]') -> 'None': ...


@schema_final
class Type2(RoutingType, code=Enum_Routing.Type_2_Routing_Header):
    """Header schema for IPv6-Route type 2 routing data."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=4)
    #: Addresses.
    ip: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, ip: 'IPv6Address | str | int | bytes') -> 'None': ...


@schema_final
class RPL(RoutingType, code=Enum_Routing.RPL_Source_Route_Header):
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
    addresses: 'bytes' = ListField(
        length=lambda pkt: pkt['__length__'] - pkt['pad']['pad_len'],
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: pkt['pad']['pad_len'])

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        buffer = cast('bytes', self.ip)
        dst_val = cast('Optional[IPv6Address]', packet.get('dst'))
        dst = dst_val.packed if dst_val is not None else None

        ilen = 16 - self.cmpr_i
        elen = 16 - self.cmpr_e
        addr = []  # type: list[IPv6Address | bytes]
        counter = 0

        # Addresses[1..n-1]
        for _ in range((len(buffer) - self.pad['pad_len'] - elen) // ilen):
            buf = buffer[counter:counter + ilen]
            if dst is None:
                if self.cmpr_i == 0:
                    addr.append(cast('IPv6Address', ipaddress.ip_address(buf)))
                else:
                    addr.append(buf)
            else:
                buf = dst[:self.cmpr_i] + buf
                addr.append(cast('IPv6Address', ipaddress.ip_address(buf)))
            counter += ilen

        # Addresses[n]
        buf = buffer[counter:counter + elen]
        if dst is None:
            if self.cmpr_e == 0:
                addr.append(cast('IPv6Address', ipaddress.ip_address(buf)))
            else:
                addr.append(buf)
        else:
            buf = dst[:self.cmpr_e] + buf
            addr.append(cast('IPv6Address', ipaddress.ip_address(buf)))

        self.ip = addr
        return self

    if TYPE_CHECKING:
        #: Addresses (SRH prefix compression decoded).
        ip: 'list[IPv6Address | bytes]'

        def __init__(self, cmpr_i: 'int', cmpr_e: 'int', pad: 'PadInfo',
                     addresses: 'list[bytes]') -> 'None': ...
