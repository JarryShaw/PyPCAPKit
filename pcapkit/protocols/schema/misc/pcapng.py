# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for pcapng file format"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.fields.collections import OptionField
from pcapkit.corekit.fields.ipaddress import IPv4AddressField, IPv4InterfaceField, IPv6AddressField, IPv6InterfaceField
from pcapkit.corekit.fields.misc import ForwardMatchField, PayloadField
from pcapkit.corekit.fields.numbers import (EnumField, Int64Field, Int8Field, UInt8Field, UInt16Field, UInt32Field,
                                            UInt64Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField, StringField
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = [
    'PCAPNG',

    'Option', 'UnknownOption',
    'EndOfOption', 'CommentOption',
    'IF_NameOption', 'IF_DescriptionOption', 'IF_IPv4AddrOption', 'IF_IPv6AddrOption',
    'IF_MACAddrOption', 'IF_EUIAddrOption', 'IF_SpeedOption', 'IF_TSResolOption',
    'IF_TZoneOption', 'IF_FilterOption', 'IF_OSOption', 'IF_FCSLenOption',
    'IF_TSOffsetOption', 'IF_HardwareOption', 'IF_TxSpeedOption', 'IF_RxSpeedOption',

    'UnknownBlock', 'SectionHeaderBlock', 'InterfaceDescriptionBlock',
]

if TYPE_CHECKING:
    from typing import IO, Any
    from ipaddress import IPv4Interface, IPv6Interface

    from typing_extensions import Self

    from pcapkit.corekit.fields.numbers import NumberField

if SPHINX_TYPE_CHECKING:
    from typing_extensions import TypedDict

    class ByteorderTest(TypedDict):
        """Test for byteorder."""

        #: Byteorder magic number.
        byteorder: int

    class ResolutionData(TypedDict):
        """Data for resolution."""

        #: Resolution type flag (0: 10-based, 1: 2-based).
        flag: int
        #: Resolution value.
        resolution: int


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
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


class UnknownOption(Option):
    """Header schema for unknown PCAP-NG file options."""

    #: Option value.
    data: 'bytes' = PayloadField(length=lambda pkt: pkt['length'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', data: 'bytes', padding: 'bytes') -> 'None': ...


class EndOfOption(Option):
    """Header schema for PCAP-NG file ``opt_endofopt`` options."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int') -> 'None': ...


class CommentOption(Option):
    """Header schema for PCAP-NG file ``opt_comment`` options."""

    comment: 'bytes' = BytesField(length=lambda pkt: pkt['length'])
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


class IF_NameOption(Option):
    """Header schema for PCAP-NG file ``if_name`` options."""

    #: Interface name.
    name: 'str' = StringField(length=lambda pkt: pkt['length'], encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', name: 'bytes', padding: 'bytes') -> 'None': ...


class IF_DescriptionOption(Option):
    """Header schema for PCAP-NG file ``if_description`` options."""

    #: Interface description.
    desc: 'str' = StringField(length=lambda pkt: pkt['length'], encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', desc: 'bytes', padding: 'bytes') -> 'None': ...


class IF_IPv4AddrOption(Option):
    """Header schema for PCAP-NG file ``if_IPv4addr`` options."""

    #: IPv4 interface.
    interface: 'IPv4Interface' = IPv4InterfaceField()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', interface: 'IPv4Interface') -> 'None': ...


class IF_IPv6AddrOption(Option):
    """Header schema for PCAP-NG file ``if_IPv6addr`` options."""

    #: IPv6 interface.
    interface: 'IPv6Interface' = IPv6InterfaceField()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', interface: 'IPv6Interface') -> 'None': ...


class IF_MACAddrOption(Option):
    """Header schema for PCAP-NG file ``if_MACaddr`` options."""

    #: MAC interface.
    mac: 'bytes' = BytesField(length=6)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', interface: 'bytes') -> 'None': ...


class IF_EUIAddrOption(Option):
    """Header schema for PCAP-NG file ``if_EUIaddr`` options."""

    #: EUI interface.
    eui: 'bytes' = BytesField(length=8)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', interface: 'bytes') -> 'None': ...


class IF_SpeedOption(Option):
    """Header schema for PCAP-NG file ``if_speed`` options."""

    #: Interface speed, in bits per second.
    speed: 'int' = UInt64Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', speed: 'int') -> 'None': ...


class IF_TSResolOption(Option):
    """Header schema for PCAP-NG file ``if_tsresol`` options."""

    #: Interface timestamp resolution, in units per second.
    tsresol: 'ResolutionData' = BitField(length=1, namespace={
        'flag': (0, 1),
        'resolution': (1, 7),
    })
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    @classmethod
    def post_process(cls, schema: 'Self', data: 'IO[bytes]',
                     length: 'int', packet: 'dict[str, Any]') -> 'Self':
        """Revise ``schema`` data after unpacking process.

        Args:
            schema: parsed schema
            data: Packed data.
            length: Length of data.
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        base = 10 if packet['tsresol']['flag'] == 0 else 2
        schema.resolution = base ** packet['tsresol']['resolution']
        return schema

    if TYPE_CHECKING:
        #: Interface timestamp resolution, in units per second.
        resolution: 'int'

        def __init__(self, type: 'int', length: 'int', tsresol: 'ResolutionData') -> 'None': ...


class IF_TZoneOption(Option):
    """Header schema for PCAP-NG file ``if_tzone`` options."""

    #: Interface time zone.
    tzone: 'int' = UInt32Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', tzone: 'int') -> 'None': ...


class IF_FilterOption(Option):
    """Header schema for PCAP-NG file ``if_filter`` options."""

    #: Filter code.
    code: 'int' = UInt8Field(callback=byteorder_callback)
    #: Capture filter.
    filter: 'str' = StringField(length=lambda pkt: pkt['length'] - 1, encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', code: 'int', filter: 'str') -> 'None': ...


class IF_OSOption(Option):
    """Header schema for PCAP-NG file ``if_os`` options."""

    #: OS information.
    os: 'str' = StringField(length=lambda pkt: pkt['length'], encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', os: 'str') -> 'None': ...


class IF_FCSLenOption(Option):
    """Header schema for PCAP-NG file ``if_fcslen`` options."""

    #: FCS length.
    fcslen: 'int' = UInt8Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', fcslen: 'int') -> 'None': ...


class IF_TSOffsetOption(Option):
    """Header schema for PCAP-NG file ``if_tsoffset`` options."""

    #: Timestamp offset (in seconds).
    tsoffset: 'int' = Int64Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', tsoffset: 'int') -> 'None': ...


class IF_HardwareOption(Option):
    """Header schema for PCAP-NG file ``if_hardware`` options."""

    #: Hardware information.
    hardware: 'str' = StringField(length=lambda pkt: pkt['length'], encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', hardware: 'str') -> 'None': ...


class IF_TxSpeedOption(Option):
    """Header schema for PCAP-NG file ``if_txspeed`` options."""

    #: Interface transmit speed, in bits per second.
    tx_speed: 'int' = UInt64Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', tx_speed: 'int') -> 'None': ...


class IF_RxSpeedOption(Option):
    """Header schema for PCAP-NG file ``if_rxspeed`` options."""

    #: Interface receive speed, in bits per second.
    rx_speed: 'int' = UInt64Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', rx_speed: 'int') -> 'None': ...


class InterfaceDescriptionBlock(PCAPNG):
    """Header schema for PCAP-NG Interface Description Block (IDB)."""

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Link type.
    linktype: 'Enum_LinkType' = EnumField(length=2, namespace=Enum_LinkType, callback=byteorder_callback)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Snap length.
    snaplen: 'int' = UInt32Field(default=0, callback=byteorder_callback)
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['length'] - 20,
        base_schema=Option,
        type_name='type',
        registry=collections.defaultdict(lambda: UnknownOption, {
            Enum_OptionType.opt_endofopt: EndOfOption,
            Enum_OptionType.opt_comment: CommentOption,
            Enum_OptionType.if_name: IF_NameOption,
            Enum_OptionType.if_description: IF_DescriptionOption,
            Enum_OptionType.if_IPv4addr: IF_IPv4AddrOption,
            Enum_OptionType.if_IPv6addr: IF_IPv6AddrOption,
            Enum_OptionType.if_MACaddr: IF_MACAddrOption,
            Enum_OptionType.if_EUIaddr: IF_EUIAddrOption,
            Enum_OptionType.if_speed: IF_SpeedOption,
            Enum_OptionType.if_tsresol: IF_TSResolOption,
            Enum_OptionType.if_tzone: IF_TZoneOption,
            Enum_OptionType.if_filter: IF_FilterOption,
            Enum_OptionType.if_os: IF_OSOption,
            Enum_OptionType.if_fcslen: IF_FCSLenOption,
            Enum_OptionType.if_tsoffset: IF_TSOffsetOption,
            Enum_OptionType.if_hardware: IF_HardwareOption,
            Enum_OptionType.if_txspeed: IF_TxSpeedOption,
            Enum_OptionType.if_rxspeed: IF_RxSpeedOption,
        }),
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_BlockType', length: 'int', linktype: 'int', reserved: 'int',
                     snaplen: 'int', options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...
