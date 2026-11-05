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
from pcapkit.protocols.schema import EnumSchema, Schema, schema_final
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
    :func:`ipv6_route_data_selector` hands to the nested
    :class:`~pcapkit.protocols.internet.ipv6_route.schema.RoutingType` schema -- is ``4 + 8 *
    hdr_ext_len`` octets. This is the single place that arithmetic is done on the read side; see
    :meth:`~pcapkit.protocols.internet.ipv6_route.protocol.IPv6_Route._make_hdr_ext_len` for its inverse on
    the write side. Dropping the ``4 +`` would leave the data length 4 octets short.

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
    :mod:`pcapkit.protocols.internet.ipv6_route.protocol` reports back as the parsed
    route data's own ``.length``, which
    :meth:`~pcapkit.protocols.internet.ipv6_route.protocol.IPv6_Route.read` then
    subtracts from the outer packet length to find the next layer's length.
    Its inverse is the ``(length - 8) // 8`` that
    :meth:`~pcapkit.protocols.internet.ipv6_route.protocol.IPv6_Route._make_data`
    passes back as ``hdr_ext_len``;
    :meth:`~pcapkit.protocols.internet.ipv6_route.protocol.IPv6_Route._make_hdr_ext_len`
    inverts :func:`ipv6_route_data_length` instead.

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
        :class:`~pcapkit.protocols.internet.ipv6_route.schema.RoutingType`
        instance based on :attr:`IPv6_Route.type <pcapkit.protocols.internet.ipv6_route.schema.IPv6_Route.type>`.

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
    #: Home address.
    ip: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, reserved: 'bytes', ip: 'IPv6Address | str | int | bytes') -> 'None': ...


@schema_final
class RPL(RoutingType, code=Enum_Routing.RPL_Source_Route_Header):
    """Header schema for IPv6-Route RPL routing data.

    .. versionremoved:: 1.5.0

       ``cmpr_i`` and ``cmpr_e``, which are the keys of :attr:`cmpr`
       (:issue:`1456`).

    """

    #: CmprI and CmprE -- two 4-bit counts sharing one octet.
    #:
    #: NOTE: :rfc:`6554#section-3` gives each as a *"4-bit unsigned integer"*,
    #: the high and low nibble of one octet. With :attr:`pad` -- ``Pad`` (4 bits)
    #: and ``Reserved`` (20 bits) -- they form the 32-bit word that section
    #: draws; the split falls on the octet boundary between ``CmprE`` and ``Pad``.
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
        # NOTE: Keep the declared span (``4 + Hdr Ext Len * 8``) for post_process, which
        # splits ``Addresses[1..n]`` by it: by then ``__length__`` is counted down to zero.
        # pack calls this before setting ``__length__``, and needs no span.
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
            # NOTE: Built via ``make`` (IPv6_Route._make_data_type_rpl), ``addresses`` is a
            # ``list[bytes]`` of already-compressed addresses, which Schema.pack packs as is,
            # so there is nothing to decompress.
            #
            # NOTE: ``ip`` must still be set: Protocol.__post_init__ packs then unpacks, and
            # IPv6_Route.read hands *this* schema to _read_data_type_rpl, which would raise
            # AttributeError without it. A full-width (16-octet) item is decoded as the parse
            # path decodes an uncompressed one; anything else passes through untouched.
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

        # NOTE: Split by the span ``Hdr Ext Len`` declares, less ``pad_len``, not by the
        # octets read: on a truncated capture the latter decodes ``Addresses[1]`` as
        # ``Addresses[n]``. _read_data_type_rpl rejects a malformed span, so it is only
        # clamped here.
        declared = packet.get('__rpl_length__', len(buffer) + 4 + self.pad['pad_len'])
        area = max(declared - 4 - self.pad['pad_len'], 0)
        widths = [ilen] * (max(area - elen, 0) // ilen) + [elen]

        # NOTE: Only an item read at full width is decoded. A truncated one stays the raw
        # octets read, without the ``dst`` prefix, so a rebuild writes them back; one cut
        # off entirely is not listed.
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
