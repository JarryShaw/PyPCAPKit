# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for internet group management protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.igmp.type import Type as Enum_Type
from pcapkit.corekit.fields.ipaddress import IPv4AddressField
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['IGMP']

if TYPE_CHECKING:
    from ipaddress import IPv4Address

    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class IGMP(Schema):
    """Header schema for IGMP packet.

    The same 8-octet layout serves IGMPv1 (:rfc:`1112#page-11`) and IGMPv2
    (:rfc:`2236#section-2`): v1 leaves :attr:`max_resp_time` reserved at zero
    rather than omitting the octet (:issue:`2439`).

    """

    #: Message type.
    type: 'Enum_Type' = EnumField(length=1, namespace=Enum_Type)
    #: Max response time, in units of 1/10 second (zero/reserved outside an
    #: IGMPv2 Membership Query).
    max_resp_time: 'int' = UInt8Field()
    #: Checksum. The 16-bit one's complement of the one's complement sum of
    #: the message, with the checksum field itself taken as zero and no
    #: pseudo-header involved -- the 8-octet message itself for IGMPv1
    #: (:rfc:`1112#page-11`), or the whole IP payload for IGMPv2
    #: (:rfc:`2236#section-2.3`).
    checksum: 'bytes' = BytesField(length=2)
    #: Group address.
    group: 'IPv4Address' = IPv4AddressField()
    #: Payload, empty for a standards-conformant IGMPv1/v2 message, since the
    #: 8-octet header is the whole message.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', max_resp_time: 'int', checksum: 'bytes',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     group: 'IPv4Address | str | bytes | int',
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
