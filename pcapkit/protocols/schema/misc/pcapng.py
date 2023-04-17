# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for pcapng file format"""

from typing import TYPE_CHECKING

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import (EnumField, UInt8Field, UInt16Field, UInt32Field,
                                            UInt64Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema

__all__ = [
    'PCAPNG',

    'UnknownBlock',
]


class PCAPNG(Schema):
    """Header schema for PCAP-NG file blocks."""

    #: Block type.
    type: 'Enum_BlockType' = EnumField(length=4, namespace=Enum_BlockType)
    #: Block total length.
    length: 'int' = UInt32Field()


class UnknownBlock(PCAPNG):
    """Header schema for unknown PCAP-NG file blocks."""

    #: Block body (including padding).
    body: 'bytes' = PayloadField(length=lambda pkt: pkt['length'])
    #: Block total length.
    length2: 'int' = UInt32Field()

    def __init__(self, type: 'Enum_BlockType', length: 'int', body: 'bytes', length2: 'int') -> 'None': ...
