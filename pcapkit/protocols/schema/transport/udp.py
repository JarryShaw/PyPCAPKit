# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for user datagram protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import UInt16Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema

__all__ = ['UDP']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import Protocol


class UDP(Schema):
    """Header schema for UDP packet."""

    #: Source port.
    srcport: 'int' = UInt16Field()
    #: Destination port.
    dstport: 'int' = UInt16Field()
    #: Length of UDP packet.
    len: 'int' = UInt16Field()
    #: Checksum of UDP packet.
    checksum: 'bytes' = BytesField(length=2)
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, srcport: 'int', dstport: 'int', len: 'int',
                     checksum: 'bytes', payload: 'bytes | Schema | Protocol') -> 'None': ...
