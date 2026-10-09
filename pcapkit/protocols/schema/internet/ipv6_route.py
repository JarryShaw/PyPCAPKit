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
    from pcapkit.protocols.protocol import ProtocolBase

if SPHINX_TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import TypedDict

    class CmprInfo(TypedDict):
        """Prefix-compression counts, two nibbles of a single octet."""

        cmpr_i: int
        cmpr_e: int

    class PadInfo(TypedDict):
        """Padding length and reserved."""

        pad_len: int
        reserved: int


def ipv6_route_data_length(hdr_ext_len: 'int') -> 'int':
    """Length, in octets, of the IPv6-Route type-specific data for a given ``Hdr Ext Len``.

    Per :rfc:`8200#section-4.4`, ``Hdr Ext Len`` is *"the length of the
    Routing header in 8-octet units, not including the first 8 octets"* --
    i.e. the total on-the-wire header is ``8 + 8 * hdr_ext_len`` octets. Of
    that, the 4 octets of ``next``/``length``/``type``/``seg_left`` are not
    part of the type-specific data, so the data itself -- what
    :func:`ipv6_route_data_selector` hands to the nested ``RoutingType``
    schema -- is ``4 + 8 * hdr_ext_len`` octets. This is the single place
    that arithmetic is done on the read side; see
    :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._make_hdr_ext_len`
    for its inverse on the write side. Dropping the ``4 +`` would leave the data
    length 4 octets short.

    Args:
        hdr_ext_len: raw ``Hdr Ext Len`` field value, as read off the wire.

    Returns:
        Length, in octets, of the type-specific data.

    """
    return 4 + hdr_ext_len * 8


def ipv6_route_header_length(hdr_ext_len: 'int') -> 'int':
    """Total length, in octets, of the on-the-wire IPv6-Route header for a given ``Hdr Ext Len``.

    This is the fixed 4 octets of ``next``/``length``/``type``/``seg_left``
    plus the type-specific data computed by :func:`ipv6_route_data_length`,
    i.e. ``4 + (4 + 8 * hdr_ext_len)`` -- a *different* quantity from
    :func:`ipv6_route_data_length` itself (``8 + 8 * hdr_ext_len`` here vs.
    ``4 + 8 * hdr_ext_len`` there), not a duplicate of it. It is what each
    ``_read_data_type_*`` in
    :mod:`pcapkit.protocols.internet.ipv6_route` reports back as the parsed
    route data's own ``.length``, which :meth:`~pcapkit.protocols.internet.
    ipv6_route.IPv6_Route.read` then subtracts from the outer packet length
    to find the next layer's length. It is the read-side counterpart of
    :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._make_hdr_ext_len`,
    which does the inverse arithmetic on the write side.

    Args:
        hdr_ext_len: raw ``Hdr Ext Len`` field value, as read off the wire.

    Returns:
        Total length, in octets, of the on-the-wire IPv6-Route header.

    """
    return 4 + ipv6_route_data_length(hdr_ext_len)


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
    return SchemaField(length=ipv6_route_data_length(cast('int', pkt['length'])), schema=schema)


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
                     seg_left: 'int', data: 'bytes | RoutingType', payload: 'ProtocolBase | Schema | bytes') -> 'None': ...


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
        def __init__(self, reserved: 'bytes', ip: 'list[IPv6Address | str | int | bytes]') -> 'None': ...


@schema_final
class Type2(RoutingType, code=Enum_Routing.Type_2_Routing_Header):
    """Header schema for IPv6-Route type 2 routing data."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=4)
    #: Addresses.
    ip: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, reserved: 'bytes', ip: 'IPv6Address | str | int | bytes') -> 'None': ...


@schema_final
class RPL(RoutingType, code=Enum_Routing.RPL_Source_Route_Header):
    """Header schema for IPv6-Route RPL routing data."""

    #: CmprI and CmprE -- two 4-bit counts sharing one octet.
    #:
    #: NOTE: :rfc:`6554#section-3` gives ``CmprI`` and ``CmprE`` as *"4-bit
    #: unsigned integer"*, i.e. the high and low nibble of a single octet, so
    #: they cannot be two :class:`~pcapkit.corekit.fields.numbers.UInt8Field`
    #: (one octet each). Together with :attr:`pad` below -- ``Pad``
    #: (4 bits) plus ``Reserved`` (20 bits) -- this is the one 32-bit word the
    #: diagram in :rfc:`6554#section-3` draws, and the same word
    #: :meth:`IPv6_Route._read_data_type_rpl
    #: <pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_rpl>`'s
    #: own docstring draws. The split between the two fields falls on the octet
    #: boundary between ``CmprE`` and ``Pad``, so neither straddles an octet.
    cmpr: 'CmprInfo' = BitField(length=1, namespace={
        'cmpr_i': (0, 4),
        'cmpr_e': (4, 4),
    })
    #: Padding length and reserved.
    pad: 'PadInfo' = BitField(length=3, namespace={
        'pad_len': (0, 4),
        'reserved': (4, 20),
    })
    #: Addresses.
    addresses: 'bytes' = ListField(
        length=lambda pkt: pkt['__length__'] - pkt['pad']['pad_len'],
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: pkt['pad']['pad_len'])

    @classmethod
    def pre_unpack(cls, packet: 'dict[str, Any]') -> 'None':
        """Prepare ``packet`` data for unpacking process.

        Args:
            packet: packet data

        """
        # NOTE: The declared span -- ``4 + Hdr Ext Len * 8`` octets inside
        # IPv6-Route -- is kept for :meth:`post_process`, which splits
        # ``Addresses[1..n]`` by it. By then ``__length__`` has been counted
        # down to zero, and the octets actually read are fewer than declared
        # whenever the capture ends inside the address list. :meth:`pack` calls
        # this too, before it has set ``__length__``; the packing path does not
        # need the span, so nothing is kept there.
        if '__length__' in packet:
            packet['__rpl_length__'] = packet['__length__']

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        buffer = self.addresses
        if not isinstance(buffer, bytes):
            # NOTE: ``self.addresses`` is still a ``list[bytes]`` -- one
            # already-compressed address per item -- when this schema was
            # built via ``make`` (see
            # :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._make_data_type_rpl`)
            # rather than parsed off the wire. There is nothing to decode in
            # that case: the caller supplied each address already
            # compressed, and :meth:`Schema.pack
            # <pcapkit.protocols.schema.schema.Schema.pack>`'s own
            # :class:`~pcapkit.corekit.fields.collections.ListField` handling
            # packs that list directly. The SRH prefix-decompression below
            # only makes sense against the raw octets a real parse hands
            # here.
            #
            # NOTE: ``ip`` still has to be *set*, though, rather than merely
            # left alone. :meth:`Protocol.__post_init__
            # <pcapkit.protocols.protocol.Protocol.__post_init__>` packs and
            # then unpacks, and :meth:`IPv6_Route.read
            # <pcapkit.protocols.internet.ipv6_route.IPv6_Route.read>` hands
            # :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_rpl`
            # *this* schema on that path, not a re-parsed one -- so returning
            # early without ``ip`` would raise a bare ``AttributeError`` from
            # the reader. Each item is one whole element of
            # ``Addresses[1..n]``, so a full-width (16-octet) item is decoded
            # the way the parse path below decodes an uncompressed one, and a
            # compressed suffix is left as :obj:`bytes` -- which is exactly what
            # that path does too. The :func:`isinstance` test keeps anything
            # that is not :obj:`bytes` passing through untouched, rather than
            # failing here on a :func:`len` the item may not support.
            self.ip = [
                cast('IPv6Address', ipaddress.ip_address(item))
                if isinstance(item, bytes) and len(item) == 16 else item
                for item in buffer
            ]
            return self

        dst_val = cast('Optional[IPv6Address]', packet.get('dst'))
        dst = dst_val.packed if dst_val is not None else None

        cmpr_i = self.cmpr['cmpr_i']
        cmpr_e = self.cmpr['cmpr_e']

        ilen = 16 - cmpr_i
        elen = 16 - cmpr_e

        # NOTE: The address list is split by the span ``Hdr Ext Len`` declares,
        # not by the octets actually read: once a capture ends inside the list
        # the two differ, and splitting by the latter decodes the octets of
        # ``Addresses[1]`` as ``Addresses[n]`` (or a short run as an IPv4
        # address). The declared span is what :attr:`addresses`'s own
        # ``length`` callback asked for -- ``pad_len`` already subtracted, the
        # trailing padding octets being read by :attr:`padding` -- and a
        # malformed one (no whole number of addresses) is rejected by
        # :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_rpl`,
        # so it is only clamped here.
        declared = packet.get('__rpl_length__', len(buffer) + 4 + self.pad['pad_len'])
        area = max(declared - 4 - self.pad['pad_len'], 0)
        widths = [ilen] * (max(area - elen, 0) // ilen) + [elen]

        # NOTE: Only an item read at its full width is decoded. One the capture
        # cut short stays the raw :obj:`bytes` that were read -- not prefixed
        # with ``dst``, so a rebuild writes back exactly those octets -- and
        # one cut off entirely is not listed at all.
        addr = []  # type: list[IPv6Address | bytes]
        counter = 0
        for index, width in enumerate(widths):
            buf = buffer[counter:counter + width]
            counter += width
            if not buf:
                break
            if len(buf) < width:
                addr.append(buf)
                break

            cmpr = cmpr_e if index == len(widths) - 1 else cmpr_i
            if dst is not None:
                addr.append(cast('IPv6Address', ipaddress.ip_address(dst[:cmpr] + buf)))
            elif cmpr == 0:
                addr.append(cast('IPv6Address', ipaddress.ip_address(buf)))
            else:
                addr.append(buf)

        self.ip = addr
        return self

    if TYPE_CHECKING:
        #: Addresses (SRH prefix compression decoded).
        ip: 'list[IPv6Address | bytes]'

        def __init__(self, cmpr: 'CmprInfo', pad: 'PadInfo',
                     addresses: 'list[bytes]', padding: 'bytes') -> 'None': ...
