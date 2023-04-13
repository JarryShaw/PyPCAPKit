# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for frame header of PCAP file format"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import UInt32Field
from pcapkit.protocols.schema.schema import Schema

__all__ = ['Frame']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import Protocol


class Frame(Schema):
    """Frame header of PCAP file format."""

    __payload__ = 'packet'

    #: Timestamp seconds.
    ts_sec: 'int' = UInt32Field(byteorder='little')
    #: Timestamp microseconds.
    ts_usec: 'int' = UInt32Field(byteorder='little')
    #: Number of octets of packet saved in file.
    incl_len: 'int' = UInt32Field(byteorder='little')
    #: Actual length of packet.
    orig_len: 'int' = UInt32Field(byteorder='little')
    #: Payload.
    packet: 'bytes' = PayloadField(length=lambda pkt: pkt['incl_len'])

    if TYPE_CHECKING:
        def __init__(self, ts_sec: 'int', ts_usec: 'int', incl_len: 'int',
                     orig_len: 'int', packet: 'bytes | Protocol | Schema') -> 'None': ...
