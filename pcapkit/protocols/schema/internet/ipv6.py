# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for internet protocol version 6"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.ipaddress import IPv6AddressField
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BitField
from pcapkit.protocols.schema.schema import Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = ['IPv6']

if TYPE_CHECKING:
    from ipaddress import IPv6Address

    from pcapkit.protocols.protocol import ProtocolBase as Protocol

if SPHINX_TYPE_CHECKING:
    from typing_extensions import TypedDict

    #: Version, traffic class and flow label.
    IPv6Hextet = TypedDict('IPv6Hextet', {
        #: Version.
        'version': int,
        #: Traffic class.
        'class': int,
        #: Flow label.
        'label': int,
    })


@schema_final
class IPv6(Schema):
    """Header schema for IPv6 packet."""

    #: Version, traffic class and flow label.
    hextet: 'IPv6Hextet' = BitField(length=4, namespace={
        'version': (0, 4),
        'class': (4, 8),
        'label': (8, 20),
    })
    #: Payload length.
    length: int = UInt16Field()
    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Hop limit.
    limit: int = UInt8Field()
    #: Source address.
    src: 'IPv6Address' = IPv6AddressField()
    #: Destination address.
    dst: 'IPv6Address' = IPv6AddressField()
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, hextet: 'IPv6Hextet', length: 'int', next: 'Enum_TransType',
                     limit: 'int', src: 'IPv6Address | bytes | str | int',
                     dst: 'IPv6Address | bytes | str | int',
                     payload: 'bytes | Protocol | Schema') -> None: ...
