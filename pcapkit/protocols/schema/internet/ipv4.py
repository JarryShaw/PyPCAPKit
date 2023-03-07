# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for internet protocol version 4"""

from typing import TYPE_CHECKING

from pcapkit.const.ipv6.option import Option as Enum_Option
from pcapkit.const.ipv6.router_alert import RouterAlert as Enum_RouterAlert
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.ipaddress import IPv4Field
from pcapkit.corekit.fields.misc import ConditionalField, ListField, PayloadField
from pcapkit.corekit.fields.numbers import (EnumField, NumberField, UInt8Field, UInt16Field,
                                            UInt32Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import FieldValueError

__all__ = [
    'IPv4',

    'ToSField', 'Flags',
    'OptionType',

    'UnassignedOption', 'EOOLOption', 'NOPOption',
    'SECOption', 'LSROption', 'TSOption',
    'ESECOption', 'RROption', 'SIDOption',
    'SSROption', 'MTUPOption', 'MTUROption',
    'TROption', 'RTRALTOption', 'QSOption',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Optional

    from typing_extensions import TypedDict

    from pcapkit.protocols.protocol import Protocol

    class VerIHLField(TypedDict):
        """Version and header length field."""

        #: IP version.
        version: int
        #: Internet header length.
        ihl: int

    #: Type of service field.
    ToSField = TypedDict('ToSField', {
        'pre': int,
        'del': int,
        'thr': int,
        'rel': int,
        'ecn': int,
    })

    class Flags(TypedDict):
        """Flags and fragment offset field."""

        #: Don't fragment flag.
        df: int
        #: More fragments flag.
        mf: int
        #: Fragment offset.
        offset: int


class IPv4(Schema):
    """Header schema for IPv4 packet."""

    #: Version and header length.
    vihl: 'VerIHLField' = BitField(length=1, namespace={
        'version': (0, 4),
        'ihl': (4, 8),
    })
    #: Type of service.
    tos: 'ToSField' = BitField(length=1, namespace={
        'pre': (0, 3),
        'del': (3, 1),
        'thr': (4, 1),
        'rel': (5, 1),
        'ecn': (6, 2),
    })
    #: Total length.
    length: 'int' = UInt16Field()
    #: Identification.
    id: 'int' = UInt16Field()
    #: Flags and fragment offset.
    flags: 'Flags' = BitField(length=2, namespace={
        'df': (1, 1),
        'mf': (2, 1),
        'offset': (3, 13),
    })
    #: Time to live.
    ttl: 'int' = UInt8Field()
    #: Protocol.
    proto: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Header checksum.
    chksum: 'bytes' = BytesField(length=2)
    #: Source address.
    src: 'IPv4Address' = IPv4Field()
    #: Destination address.
    dst: 'IPv4Address' = IPv4Field()
    #: Options.
    options: 'list[Option]' = ListField(length=lambda pkt: pkt['vihl']['ihl'] * 4 - 20)
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['length'] - pkt['vihl']['ihl'] * 4)

    if TYPE_CHECKING:
        def __init__(self, vihl: 'VerIHLField', tos: 'ToSField', length: 'int', id: 'int',
                     flags: 'Flags', ttl: 'int', proto: 'Enum_TransType', chksum: 'bytes',
                     src: 'IPv4Address | str | bytes | int', dst: 'IPv4Address | str | bytes | int',
                     options: 'list[Option | bytes] | bytes', payload: 'bytes | Protocol | Schema') -> 'None': ...


class Option(Schema):
    """Header schema for IPv4 options."""
