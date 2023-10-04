# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for L2TP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.corekit.fields.numbers import UInt16Field
from pcapkit.corekit.fields.strings import BitField, PaddingField
from pcapkit.protocols.schema.schema import Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = ['L2TP']

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.protocols.protocol import ProtocolBase as Protocol

if SPHINX_TYPE_CHECKING:
    from typing_extensions import Literal, TypedDict

    class FlagsType(TypedDict):
        """Flags of L2TP packet."""

        #: Type of L2TP packet.
        type: int
        #: Length of L2TP packet.
        len: int
        #: Sequence number of L2TP packet.
        seq: int
        #: Offset size of L2TP packet.
        offset: int
        #: Priority of L2TP packet.
        prio: int
        #: Version of L2TP packet.
        version: Literal[2]


@schema_final
class L2TP(Schema):
    """Header schema for L2TP packet."""

    #: Flags and version of L2TP packet.
    flags: 'FlagsType' = BitField(length=2, namespace={
        'type': (0, 1),
        'len': (1, 1),
        'seq': (4, 1),
        'offset': (6, 1),
        'prio': (7, 1),
        'version': (12, 4),
    })
    #: Length of L2TP packet.
    length: 'int' = ConditionalField(
        UInt16Field(),
        lambda packet: packet['flags']['len'],
    )
    #: Tunnel ID of L2TP packet.
    tunnel_id: 'int' = UInt16Field()
    #: Session ID of L2TP packet.
    session_id: 'int' = UInt16Field()
    #: Sequence number of L2TP packet.
    ns: 'int' = ConditionalField(
        UInt16Field(),
        lambda packet: packet['flags']['seq'],
    )
    #: Next sequence number of L2TP packet.
    nr: 'int' = ConditionalField(
        UInt16Field(),
        lambda packet: packet['flags']['seq'],
    )
    #: Offset size of L2TP packet.
    offset: 'int' = ConditionalField(
        UInt16Field(),
        lambda packet: packet['flags']['offset'],
    )
    #: Padding of L2TP packet.
    padding: 'bytes' = ConditionalField(
        PaddingField(length=lambda pkt: pkt['offset']),
        lambda packet: packet['flags']['offset'],
    )
    #: Payload of L2TP packet.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, flags: 'FlagsType', length: 'Optional[int]', tunnel_id: 'int',
                     session_id: 'int', ns: 'Optional[int]', nr: 'Optional[int]',
                     offset: 'Optional[int]', payload: 'bytes | Protocol | Schema') -> 'None': ...
