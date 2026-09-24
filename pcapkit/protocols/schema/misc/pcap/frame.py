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
    from pcapkit.protocols.protocol import ProtocolBase


def byteorder_callback(field: 'Field', packet: 'dict[str, Any]') -> 'None':
    """Update byte order of PCAP file.

    Args:
        field: Field instance.
        packet: Packet data.

    Notes:
        ``byteorder`` is the key a caller has to seed, and this function is what
        defines it: :meth:`Frame.pack <pcapkit.protocols.misc.pcap.frame.Frame.pack>`
        and :meth:`Frame.unpack <pcapkit.protocols.misc.pcap.frame.Frame.unpack>`
        both write it from the global header's magic number. The fallback to
        :data:`sys.byteorder` is for a schema packed or unpacked on its own, with
        no global header to ask -- which also means a *misspelled* key looks
        exactly like an absent one and reports nothing. That is what hid GitHub
        issue #605: ``unpack`` wrote ``bytesorder``, so every field here was read
        in the host's order rather than the file's, which is right by coincidence
        on a little-endian capture and byte-swapped on a big-endian one. See
        :file:`tests/protocols/misc/pcap/test_frame_endian_runtime.py` for the
        fixtures that now take the other side of the branch.

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
                     orig_len: 'int', packet: 'bytes | ProtocolBase | Schema') -> 'None': ...
