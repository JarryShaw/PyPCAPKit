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

if SPHINX_TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import TypedDict

    class CmprInfo(TypedDict):
        """Prefix-compression counts, two nibbles of a single octet."""

        cmpr_i: int
        cmpr_e: int

    class PadInfo(TypedDict):
        """Padding length and reserved."""

        pad_len: int


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
    for its inverse on the write side. Do NOT drop the ``4 +``: that turns
    the field back into raw octets and is the exact defect #487 fixed.

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
    to find the next layer's length. #489 unified the write side
    (:meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._make_hdr_ext_len`)
    into one helper; this is the matching read-side helper for the total
    header length, finishing that half of #487/#489.

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

    #: CmprI and CmprE -- two 4-bit counts sharing one octet.
    #:
    #: NOTE: :rfc:`6554#section-3` gives ``CmprI`` and ``CmprE`` as *"4-bit
    #: unsigned integer"*, i.e. the high and low nibble of a single octet, so
    #: they cannot be two :class:`~pcapkit.corekit.fields.numbers.UInt8Field`
    #: as they were before #564. Together with :attr:`pad` below -- ``Pad``
    #: (4 bits) plus ``Reserved`` (20 bits) -- this is the one 32-bit word the
    #: diagram in :rfc:`6554#section-3` draws, and the same word
    #: :meth:`IPv6_Route._read_data_type_rpl
    #: <pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_rpl>`'s
    #: own docstring already drew correctly. The split between the two fields
    #: falls on the octet boundary between ``CmprE`` and ``Pad``, so neither
    #: straddles an octet.
    cmpr: 'CmprInfo' = BitField(length=1, namespace={
        'cmpr_i': (0, 4),
        'cmpr_e': (4, 4),
    })
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
            # here -- treating the list as ``bytes`` (as a bare ``cast``
            # used to, without a runtime check) raised trying to slice and
            # re-join it. See #556.
            #
            # NOTE: ``ip`` still has to be *set*, though, rather than merely
            # left alone. :meth:`Protocol.__post_init__
            # <pcapkit.protocols.protocol.Protocol.__post_init__>` packs and
            # then unpacks, and :meth:`IPv6_Route.read
            # <pcapkit.protocols.internet.ipv6_route.IPv6_Route.read>` hands
            # :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_rpl`
            # *this* schema on that path, not a re-parsed one -- so returning
            # early without ``ip`` raised a bare ``AttributeError: 'RPL'
            # object has no attribute 'ip'`` from the reader. That was masked
            # for as long as the reader's ``% 16`` guard rejected every
            # constructed header first; fixing the guard alongside #564
            # exposed it, so it is fixed in the same pass. Each item is one
            # whole element of ``Addresses[1..n]``, so a full-width (16-octet)
            # item is decoded the way the parse path below decodes an
            # uncompressed one, and a compressed suffix is left as
            # :obj:`bytes` -- which is exactly what that path does too. The
            # :func:`isinstance` test keeps anything that is not :obj:`bytes`
            # passing through untouched, as it did when this branch returned
            # without setting ``ip`` at all, rather than failing here on a
            # :func:`len` the item may not support.
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
        addr = []  # type: list[IPv6Address | bytes]
        counter = 0

        # Addresses[1..n-1]
        #
        # NOTE: ``buffer`` is ``self.addresses``, whose own ``length`` callback
        # above already subtracted ``pad_len`` -- the trailing padding octets
        # are read by :attr:`padding`, not by this field. Subtracting
        # ``pad_len`` a *second* time here dropped one address for every
        # ``ilen`` octets of padding, so a padded (i.e. compressed) header
        # parsed one address short; measured with ``cmpr_i=cmpr_e=4`` and three
        # addresses, which yields ``pad_len=4`` and walked one element instead
        # of two. Only reachable once the ``% 16`` guard in
        # :meth:`IPv6_Route._read_data_type_rpl
        # <pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_rpl>`
        # stopped rejecting every such header, which is why it is fixed in the
        # same pass as #564.
        for _ in range((len(buffer) - elen) // ilen):
            buf = buffer[counter:counter + ilen]
            if dst is None:
                if cmpr_i == 0:
                    addr.append(cast('IPv6Address', ipaddress.ip_address(buf)))
                else:
                    addr.append(buf)
            else:
                buf = dst[:cmpr_i] + buf
                addr.append(cast('IPv6Address', ipaddress.ip_address(buf)))
            counter += ilen

        # Addresses[n]
        buf = buffer[counter:counter + elen]
        if dst is None:
            if cmpr_e == 0:
                addr.append(cast('IPv6Address', ipaddress.ip_address(buf)))
            else:
                addr.append(buf)
        else:
            buf = dst[:cmpr_e] + buf
            addr.append(cast('IPv6Address', ipaddress.ip_address(buf)))

        self.ip = addr
        return self

    if TYPE_CHECKING:
        #: Addresses (SRH prefix compression decoded).
        ip: 'list[IPv6Address | bytes]'

        def __init__(self, cmpr: 'CmprInfo', pad: 'PadInfo',
                     addresses: 'list[bytes]') -> 'None': ...
