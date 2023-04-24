# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for pcapng file format"""

import collections
import sys
from msilib import schema
from typing import TYPE_CHECKING

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
from pcapkit.corekit.fields.collections import OptionField
from pcapkit.corekit.fields.misc import ForwardMatchField, PayloadField
from pcapkit.corekit.fields.numbers import (EnumField, UInt8Field, UInt16Field, UInt32Field,
                                            UInt64Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = [
    'PCAPNG',

    'Option', 'UnknownOption', 'EndOfOption', 'CommentOption',

    'UnknownBlock', 'SectionHeaderBlock',
]

if TYPE_CHECKING:
    from typing import IO, Any

    from typing_extensions import Self

    from pcapkit.corekit.fields.numbers import NumberField

if SPHINX_TYPE_CHECKING:
    from typing_extensions import TypedDict

    class ByteorderTest(TypedDict):
        """Test for byteorder."""

        byteorder: int


def byteorder_callback(field: 'NumberField', packet: 'dict[str, Any]') -> 'None':
    """Update byte order of PCAP-NG file.

    Args:
        field: Field instance.
        packet: Packet data.

    """
    field._byteorder = packet.get('byteorder', sys.byteorder)


def shb_byteorder_callback(field: 'NumberField', packet: 'dict[str, Any]') -> 'None':
    """Update byte order of PCAP-NG file for SHB.

    Args:
        field: Field instance.
        packet: Packet data.

    """
    magic = packet['match']['byteorder']  # type: int
    if magic == 0x1A2B3C4D:
        field._byteorder = 'big'
    elif magic == 0x4D3C2B1A:
        field._byteorder = 'little'
    else:
        raise ProtocolError(f'unknown byteorder magic: {magic:#x}')


class Option(Schema):
    """Header schema for PCAP-NG file options."""

    #: Option type.
    type: 'Enum_OptionType' = EnumField(length=2, namespace=Enum_OptionType, callback=byteorder_callback)
    #: Option length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


class UnknownOption(Option):
    """Header schema for unknown PCAP-NG file options."""

    #: Option value.
    data: 'bytes' = PayloadField(length=lambda pkt: pkt['length'] - 4)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', data: 'bytes', padding: 'bytes') -> 'None': ...


class EndOfOption(Option):
    """Header schema for PCAP-NG file end-of-option options."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int') -> 'None': ...


class CommentOption(Option):
    """Header schema for PCAP-NG file comment options."""

    comment: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 4)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', comment: 'bytes', padding: 'bytes') -> 'None': ...


class PCAPNG(Schema):
    """Header schema for PCAP-NG file blocks."""

    #: Block type.
    type: 'Enum_BlockType' = EnumField(length=4, namespace=Enum_BlockType)

    @classmethod
    def post_process(cls, schema: 'Self', data: 'IO[bytes]',
                     length: 'int', packet: 'dict[str, Any]') -> 'Self':
        """Revise ``schema`` data after unpacking process.

        This method validates the two block lengths and raises
        :exc:`~pcapkit.utilities.exceptions.ProtocolError` if they are not
        equal.

        Args:
            schema: parsed schema
            data: Packed data.
            length: Length of data.
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if schema.length != schema.length2:
            raise ProtocolError(f'block length mismatch: {schema.length} != {schema.length2}')
        return schema

    if TYPE_CHECKING:
        length: int
        length2: int


class UnknownBlock(PCAPNG):
    """Header schema for unknown PCAP-NG file blocks."""

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Block body (including padding).
    body: 'bytes' = PayloadField(length=lambda pkt: pkt['length'])
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_BlockType', length: 'int', body: 'bytes', length2: 'int') -> 'None': ...


class SectionHeaderBlock(PCAPNG):
    """Header schema for PCAP-NG Section Header Block (SHB)."""

    #: Fast forward field to test the byteorder.
    match: 'ByteorderTest' = ForwardMatchField(BitField(length=2, namespace={
        'byteorder': (32, 32),
    }))
    #: Block total length.
    length: 'int' = UInt32Field(callback=shb_byteorder_callback)
    #: Byte order magic number.
    magic: 'int' = UInt32Field(callback=shb_byteorder_callback)
    #: Major version number.
    major: 'int' = UInt16Field(callback=shb_byteorder_callback, default=1)
    #: Minor version number.
    minor: 'int' = UInt16Field(callback=shb_byteorder_callback, default=0)
    #: Section length.
    section_length: 'int' = UInt64Field(callback=shb_byteorder_callback, default=0xFFFFFFFFFFFFFFFF)
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['length'] - 28,
        base_schema=Option,
        type_name='type',
        registry=collections.defaultdict(lambda: UnknownOption, {
            Enum_OptionType.endofopt: EndOfOption,
            Enum_OptionType.comment: CommentOption,
        }),
        eool=Enum_OptionType.endofopt,
    )
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_BlockType', length: 'int', magic: 'int', major: 'int',
                     minor: 'int', section_length: 'int', options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...
