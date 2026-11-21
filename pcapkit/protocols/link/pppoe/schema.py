# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for PPP over Ethernet"""

from typing import TYPE_CHECKING

from pcapkit.const.pppoe.code import Code as Enum_Code
from pcapkit.const.pppoe.tag import Tag as Enum_Tag
from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField, SchemaField
from pcapkit.corekit.fields.numbers import EnumField, UInt16Field
from pcapkit.corekit.fields.strings import BitField, BytesField
from pcapkit.protocols.schema import Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = ['PPPoE', 'Tag']

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.protocols.protocol import ProtocolBase

if SPHINX_TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import TypedDict

    class VersionType(TypedDict):
        """Version and type of PPPoE packet."""

        #: Version.
        ver: int
        #: Type.
        type: int


def pppoe_payload_length(pkt: 'dict[str, Any]') -> 'int':
    """Length of the :attr:`PPPoE.payload` field.

    Args:
        pkt: Packet data.

    Returns:
        The Length field in the session stage, whose payload is a PPP frame;
        ``0`` in the discovery stage, whose payload is its tags.

    """
    if pkt['code'] == Enum_Code.PPP_Session_Stage:
        return pkt['length']
    return 0


@schema_final
class Tag(Schema):
    """Header schema for PPPoE discovery tags."""

    #: Tag type.
    type: 'Enum_Tag' = EnumField(length=2, namespace=Enum_Tag)
    #: Tag length.
    length: 'int' = UInt16Field()
    #: Tag value.
    value: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Tag | int', length: 'int', value: 'bytes') -> 'None': ...  # pylint: disable=redefined-builtin


@schema_final
class PPPoE(Schema):
    """Header schema for PPPoE packets."""

    #: Version and type.
    info: 'VersionType' = BitField(length=1, namespace={
        'ver': (0, 4),
        'type': (4, 4),
    })
    #: Code.
    code: 'Enum_Code' = EnumField(length=1, namespace=Enum_Code)
    #: Session ID.
    session_id: 'int' = UInt16Field()
    #: Length of the payload.
    length: 'int' = UInt16Field()
    #: Tags, in the discovery stage.
    tags: 'list[Tag]' = ConditionalField(
        ListField(
            length=lambda pkt: pkt['length'],
            item_type=SchemaField(schema=Tag),
        ),
        lambda pkt: pkt['code'] != Enum_Code.PPP_Session_Stage,
    )
    #: Payload, in the session stage.
    payload: 'bytes' = PayloadField(length=pppoe_payload_length)
    #: Octets captured past the Length field, see
    #: :attr:`L2TP.trailer <pcapkit.protocols.link.l2tp.schema.L2TP.trailer>`.
    trailer: 'bytes' = PayloadField(default=b'')

    if TYPE_CHECKING:
        def __init__(self, info: 'VersionType', code: 'Enum_Code | int', session_id: 'int',
                     length: 'int', tags: 'Optional[list[Tag]]',
                     payload: 'bytes | ProtocolBase | Schema', trailer: 'bytes' = b'') -> 'None': ...
