# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for frame header of PCAP file format"""

import sys
from typing import TYPE_CHECKING

from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import UInt32Field
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['Frame']

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.corekit.fields.numbers import NumberField as Field
    from pcapkit.protocols.protocol import ProtocolBase as Protocol


def byteorder_callback(field: 'Field', packet: 'dict[str, Any]') -> 'None':
    """Update byte order of PCAP file.

    Args:
        field: Field instance.
        packet: Packet data.

    """
    field._byteorder = packet.get('byteorder', sys.byteorder)


@schema_final
class Frame(Schema):
    """Frame header of PCAP file format."""

    __payload__ = 'packet'

    #: Timestamp seconds.
    ts_sec: 'int' = UInt32Field(callback=byteorder_callback)
    #: Timestamp microseconds.
    ts_usec: 'int' = UInt32Field(callback=byteorder_callback)
    #: Number of octets of packet saved in file.
    incl_len: 'int' = UInt32Field(callback=byteorder_callback)
    #: Actual length of packet.
    orig_len: 'int' = UInt32Field(callback=byteorder_callback)
    #: Payload.
    packet: 'bytes' = PayloadField(length=lambda pkt: pkt['incl_len'])

    if TYPE_CHECKING:
        def __init__(self, ts_sec: 'int', ts_usec: 'int', incl_len: 'int',
                     orig_len: 'int', packet: 'bytes | Protocol | Schema') -> 'None': ...
