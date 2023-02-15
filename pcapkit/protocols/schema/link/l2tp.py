# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for L2TP protocol"""

import importlib
from typing import TYPE_CHECKING, cast

from pcapkit.corekit.fields.misc import PayloadField, ConditionalField
from pcapkit.corekit.fields.numbers import UInt32Field
from pcapkit.corekit.fields.strings import BitField, PaddingField
from pcapkit.protocols.schema.schema import Schema

__all__ = ['L2TP']

if TYPE_CHECKING:
    from typing_extensions import TypedDict, Literal

    from pcapkit.protocols.protocol import Protocol


    class Flags(TypedDict):
        """Flags of L2TP packet."""

        type: int
        len: int
        seq: int
        offset: int
        prio: int
        version: Literal[2]


class L2TP(Schema):
    """Header schema for L2TP packet."""

    #: Flags and version of L2TP packet.
    flags: 'Flags' = BitField(length=2, namespace={
        'type': (0, 1),
        'len': (1, 1),
        'seq': (4, 1),
        'offset': (6, 1),
        'prio': (7, 1),
        'version': (12, 4),
    })
    #: Length of L2TP packet.
    length: 'int' = ConditionalField(
        UInt32Field(),
        lambda packet: packet['flags'].get('length', False),
    )
    #: Tunnel ID of L2TP packet.
    tunnel_id: 'int' = UInt32Field()
    #: Session ID of L2TP packet.
    session_id: 'int' = UInt32Field()
    #: Sequence number of L2TP packet.
    ns: 'int' = ConditionalField(
        UInt32Field(),
        lambda packet: packet['flags'].get('seq', False),
    )
    #: Next sequence number of L2TP packet.
    nr: 'int' = ConditionalField(
        UInt32Field(),
        lambda packet: packet['flags'].get('seq', False),
    )
    #: Offset size of L2TP packet.
    offset: 'int' = ConditionalField(
        UInt32Field(),
        lambda packet: packet['flags'].get('offset', False),
    )
    #: Padding of L2TP packet.
    padding: 'bytes' = ConditionalField(
        PaddingField(length=lambda pkt: pkt.get('offset', 0)),
        lambda packet: packet['flags'].get('offset', False),
    )
    #: Payload of L2TP packet.
    payload: 'bytes | Protocol | Schema' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, flags: 'Flags', length: 'int', tunnel_id: 'int', session_id: 'int',
                     ns: 'int', nr: 'int', offset: 'int', padding: 'bytes',
                     payload: 'bytes | Protocol | Schema') -> 'None': ...
