# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for frame header of PCAP file format"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.byteorder import byteorder_callback
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import UInt32Field
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['Frame']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase

#: Length of a PCAP record header, which precedes each record's packet data.
#: The one home of this value (:issue:`1739`); the format fixes it, so it is
#: never configurable.
#:
#: .. versionadded:: 1.5.0
RECORD_HEADER_LEN = 16


@schema_final
class Frame(Schema):
    """Frame header of PCAP file format."""

    __payload__ = 'packet'

    #: Timestamp seconds.
    ts_sec: 'int' = UInt32Field(callback=byteorder_callback)
    #: Timestamp microseconds, or nanoseconds in a nanosecond-resolution file.
    ts_usec: 'int' = UInt32Field(callback=byteorder_callback)
    #: Number of octets of packet saved in file.
    incl_len: 'int' = UInt32Field(callback=byteorder_callback)
    #: Actual length of packet.
    orig_len: 'int' = UInt32Field(callback=byteorder_callback)
    #: Payload.
    packet: 'bytes' = PayloadField(length=lambda pkt: pkt['incl_len'])

    if TYPE_CHECKING:
        def __init__(self, ts_sec: 'int', ts_usec: 'int', incl_len: 'int',
                     orig_len: 'int', packet: 'bytes | ProtocolBase | Schema') -> 'None': ...
