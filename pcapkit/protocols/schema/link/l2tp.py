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
    from typing import Any, Optional

    from pcapkit.protocols.protocol import ProtocolBase

if SPHINX_TYPE_CHECKING:  # pragma: no cover
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
        #: Reserved bits 2 and 3 of L2TP packet.
        reserved_1: int
        #: Reserved bit 5 of L2TP packet.
        reserved_2: int
        #: Reserved bits 8 to 11 of L2TP packet.
        reserved_3: int
        #: Version of L2TP packet.
        version: Literal[2]


def l2tp_payload_length(pkt: 'dict[str, Any]') -> 'int':
    """Length of the :attr:`L2TP.payload` field.

    Args:
        pkt: Packet data.

    Returns:
        The Length field less the header, when the ``L`` flag is set; otherwise
        ``-1``, so that the payload takes the rest of the datagram.

    """
    flags = pkt['flags']
    if not flags['len']:
        return -1
    size = pkt['offset'] if flags['offset'] else 0
    return pkt['length'] - (6 + 2 * (1 + 2 * flags['seq'] + flags['offset']) + size)


@schema_final
class L2TP(Schema):
    """Header schema for L2TP packet."""

    #: Flags and version of L2TP packet.
    flags: 'FlagsType' = BitField(length=2, namespace={
        'type': (0, 1),
        'len': (1, 1),
        'reserved_1': (2, 2),
        'seq': (4, 1),
        'reserved_2': (5, 1),
        'offset': (6, 1),
        'prio': (7, 1),
        'reserved_3': (8, 4),
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
    payload: 'bytes' = PayloadField(length=l2tp_payload_length)
    #: Octets captured past the Length field, c.f.
    #: :attr:`IPv4.trailer <pcapkit.protocols.schema.internet.ipv4.IPv4.trailer>`.
    #: Always empty when the ``L`` flag is clear, since the payload then takes
    #: the rest of the datagram.
    trailer: 'bytes' = PayloadField(default=b'')

    if TYPE_CHECKING:
        def __init__(self, flags: 'FlagsType', length: 'Optional[int]', tunnel_id: 'int',
                     session_id: 'int', ns: 'Optional[int]', nr: 'Optional[int]',
                     offset: 'Optional[int]', padding: 'bytes',
                     payload: 'bytes | ProtocolBase | Schema',
                     trailer: 'bytes' = b'') -> 'None': ...
