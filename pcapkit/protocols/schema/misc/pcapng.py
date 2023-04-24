# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for pcapng file format"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.const.pcapng.hash_algorithm import HashAlgorithm as Enum_HashAlgorithm
from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
from pcapkit.const.pcapng.record_type import RecordType as Enum_RecordType
from pcapkit.const.pcapng.verdict_type import VerdictType as Enum_VerdictType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.ipaddress import (IPv4AddressField, IPv4InterfaceField,
                                              IPv6AddressField, IPv6InterfaceField)
from pcapkit.corekit.fields.misc import ForwardMatchField, PayloadField
from pcapkit.corekit.fields.numbers import (EnumField, Int64Field, UInt8Field, UInt16Field,
                                            UInt32Field, UInt64Field)
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
    'EPB_FlagsOption', 'EPB_HashOption', 'EPB_DropCountOption', 'EPB_PacketIDOption',
    'EPB_QueueOption', 'EPB_VerdictOption',
    'NS_DNSNameOption', 'NS_DNSIP4AddrOption', 'NS_DNSIP6AddrOption',

    'NameResolutionRecord', 'UnknownRecord', 'EndRecord', 'IPv4Record', 'IPv6Record',

    'UnknownBlock', 'SectionHeaderBlock', 'InterfaceDescriptionBlock',
    'EnhancedPacketBlock', 'SimplePacketBlock', 'NameResolutionBlock',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
    from typing import IO, Any

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

    class EPBFlags(TypedDict):
        """EPB flags."""

        #: Inbound / Outbound packet (``00`` = information not available,
        #: ``01`` = inbound, ``10`` = outbound)
        direction: int
        #: Reception type (``000`` = not specified, ``001`` = unicast,
        #: ``010`` = multicast, ``011`` = broadcast, ``100`` = promiscuous).
        reception: int
        #: FCS length, in octets (``0000`` if this information is not available).
        #: This value overrides the ``if_fcslen`` option of the Interface Description
        #: Block, and is used with those link layers (e.g. PPP) where the length of
        #: the FCS can change during time.
        fcs_len: int
        #: Link-layer-dependent error - CRC error (bit 24).
        crc_error: int
        #: Link-layer-dependent error - packet too long error (bit 25).
        too_long: int
        #: Link-layer-dependent error - packet too short error (bit 26).
        too_short: int
        #: Link-layer-dependent error - wrong Inter Frame Gap error (bit 27).
        gap_error: int
        #: Link-layer-dependent error - unaligned frame error (bit 28).
        unaligned_error: int
        #: Link-layer-dependent error - Start Frame Delimiter error (bit 29).
        delimiter_error: int
        #: Link-layer-dependent error - preamble error (bit 30).
        preamble_error: int
        #: Link-layer-dependent error - symbol error (bit 31).
        symbol_error: int


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

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        This method validates the two block lengths and raises
        :exc:`~pcapkit.utilities.exceptions.ProtocolError` if they are not
        equal.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if self.length != self.length2:
            raise ProtocolError(f'block length mismatch: {self.length} != {self.length2}')
        return self

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

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        base = 10 if self.tsresol['flag'] == 0 else 2
        self.resolution = base ** self.tsresol['resolution']
        return self

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


class EPB_FlagsOption(Option):
    """Header schema for PCAP-NG ``epb_flags`` options."""

    #: Flags.
    flags: 'EPBFlags' = BitField(length=4, namespace={
        'direction': (0, 2),
        'reception': (2, 3),
        'fcs_len': (5, 4),
        'crc_error': (24, 1),
        'too_long': (25, 1),
        'too_short': (26, 1),
        'gap_error': (27, 1),
        'unaligned_error': (28, 1),
        'delimiter_error': (29, 1),
        'preamble_error': (30, 1),
        'symbol_error': (31, 1),
    })
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', flags: 'EPBFlags') -> 'None': ...


class EPB_HashOption(Option):
    """Header schema for PCAP-NG ``epb_hash`` options."""

    #: Hash algorithm.
    func: 'Enum_HashAlgorithm' = EnumField(length=1, namespace=Enum_HashAlgorithm, callback=byteorder_callback)
    #: Hash value.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 1)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', func: 'Enum_HashAlgorithm', data: 'bytes') -> 'None': ...


class EPB_DropCountOption(Option):
    """Header schema for PCAP-NG ``epb_dropscount`` options."""

    #: Number of packets dropped by the interface.
    drop_count: 'int' = UInt64Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', drop_count: 'int') -> 'None': ...


class EPB_PacketIDOption(Option):
    """Header schema for PCAP-NG ``epb_packetid`` options."""

    #: Packet ID.
    packet_id: 'int' = UInt64Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', packet_id: 'int') -> 'None': ...


class EPB_QueueOption(Option):
    """Header schema for PCAP-NG ``epb_queue`` options."""

    #: Queue ID.
    queue_id: 'int' = UInt32Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', queue_id: 'int') -> 'None': ...


class EPB_VerdictOption(Option):
    """Header schema for PCAP-NG ``epb_verdict`` options."""

    #: Verdict type.
    verdict: 'Enum_VerdictType' = EnumField(length=1, namespace=Enum_VerdictType, callback=byteorder_callback)
    #: Verdict value.
    value: 'int' = NumberField(length=lambda pkt: pkt['length'] - 1, callback=byteorder_callback, signed=False)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', verdict: 'Enum_VerdictType', value: 'int') -> 'None': ...


class EnhancedPacketBlock(PCAPNG):
    """Header schema for PCAP-NG Enhanced Packet Block (EPB)."""

    __payload__ = 'packet_data'

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Interface ID.
    interface_id: 'int' = UInt32Field(callback=byteorder_callback)
    #: Higher 32-bit of timestamp (in seconds).
    timestamp_high: 'int' = UInt32Field(callback=byteorder_callback)
    #: Lower 32-bit of timestamp (in seconds).
    timestamp_low: 'int' = UInt32Field(callback=byteorder_callback)
    #: Captured packet length.
    captured_len: 'int' = UInt32Field(callback=byteorder_callback)
    #: Original packet length.
    original_len: 'int' = UInt32Field(callback=byteorder_callback)
    #: Packet data.
    packet_data: 'bytes' = BytesField(length=lambda pkt: pkt['captured_len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['length'] - 32 - pkt['captured_len'] - len(pkt['padding']),
        base_schema=Option,
        type_name='type',
        registry=collections.defaultdict(lambda: UnknownOption, {
            Enum_OptionType.opt_endofopt: EndOfOption,
            Enum_OptionType.opt_comment: CommentOption,
            Enum_OptionType.epb_flags: EPB_FlagsOption,
            Enum_OptionType.epb_hash: EPB_HashOption,
            Enum_OptionType.epb_dropcount: EPB_DropCountOption,
            Enum_OptionType.epb_packetid: EPB_PacketIDOption,
            Enum_OptionType.epb_queue: EPB_QueueOption,
            Enum_OptionType.epb_verdict: EPB_VerdictOption,
        }),
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_BlockType', length: 'int', interface_id: 'int', timestamp_high: 'int',
                     timestamp_low: 'int', captured_len: 'int', original_len: 'int', packet_data: 'bytes',
                     padding: 'bytes', options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...


class SimplePacketBlock(PCAPNG):
    """Header schema for PCAP-NG Simple Packet Block (SPB)."""

    __payload__ = 'packet_data'

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Original packet length.
    original_len: 'int' = UInt32Field(callback=byteorder_callback)
    #: Packet data.
    packet_data: 'bytes' = BytesField(length=lambda pkt: min(pkt.get('snaplen', 0xFFFFFFFFFFFFFFFF), pkt['original_len']))
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_BlockType', length: 'int', original_len: 'int', packet_data: 'bytes',
                     padding: 'bytes', length2: 'int') -> 'None': ...


class NameResolutionRecord(Schema):
    """Header schema for PCAP-NG NRB records."""

    #: Record type.
    type: 'Enum_RecordType' = EnumField(length=2, namespace=Enum_RecordType, callback=byteorder_callback)
    #: Record value length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


class UnknownRecord(NameResolutionRecord):
    """Header schema for PCAP-NG NRB unknown records."""

    #: Unknown record data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_RecordType', length: 'int', data: 'bytes') -> 'None': ...


class EndRecord(NameResolutionRecord):
    """Header schema for PCAP-NG ``nrb_record_end`` records."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_RecordType', length: 'int') -> 'None': ...


class IPv4Record(NameResolutionRecord):
    """Header schema for PCAP-NG NRB ``nrb_record_ipv4`` records."""

    #: IPv4 address.
    ip: 'IPv4Address' = IPv4AddressField()
    #: Name resolution data.
    resol: 'str' = StringField(length=lambda pkt: pkt['length'] - 4)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        self.names = self.resol.split('\x00')
        return self

    if TYPE_CHECKING:
        #: Name resolution records.
        names: 'list[str]'

        def __init__(self, type: 'Enum_RecordType', length: 'int', ip: 'IPv4Address', resol: 'str', padding: 'bytes') -> 'None': ...


class IPv6Record(NameResolutionRecord):
    """Header schema for PCAP-NG NRB ``nrb_record_ipv4`` records."""

    #: IPv4 address.
    ip: 'IPv6Address' = IPv6AddressField()
    #: Name resolution data.
    resol: 'str' = StringField(length=lambda pkt: pkt['length'] - 4)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        self.names = self.resol.split('\x00')
        return self

    if TYPE_CHECKING:
        #: Name resolution records.
        names: 'list[str]'

        def __init__(self, type: 'Enum_RecordType', length: 'int', ip: 'IPv4Address', resol: 'str', padding: 'bytes') -> 'None': ...


class NS_DNSNameOption(Option):
    """Header schema for PCAP-NG ``ns_dnsname`` option."""

    #: DNS name.
    name: 'str' = StringField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_OptionType', length: 'int', name: 'str') -> 'None': ...


class NS_DNSIP4AddrOption(Option):
    """Header schema for PCAP-NG ``ns_dnsIP4addr`` option."""

    #: IPv4 address.
    ip: 'IPv4Address' = IPv4AddressField()

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_OptionType', length: 'int', ip: 'IPv4Address') -> 'None': ...


class NS_DNSIP6AddrOption(Option):
    """Header schema for PCAP-NG ``ns_dnsIP6addr`` option."""

    #: IPv6 address.
    ip: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_OptionType', length: 'int', ip: 'IPv6Address') -> 'None': ...


class NameResolutionBlock(PCAPNG):
    """Header schema for PCAP-NG Name Resolution Block (NRB)."""

    #: Record total length.
    length: 'int' = UInt16Field(callback=byteorder_callback)
    #: Name resolution records.
    records: 'list[NameResolutionRecord]' = OptionField(
        length=lambda pkt: pkt['length'],
        base_schema=NameResolutionRecord,
        type_name='type',
        registry=collections.defaultdict(lambda: UnknownRecord, {
            Enum_RecordType.nrb_record_end: EndRecord,
            Enum_RecordType.nrb_record_ipv4: IPv4Record,
            Enum_RecordType.nrb_record_ipv6: IPv6Record,
        }),
        eool=Enum_RecordType.nrb_record_end,
    )
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['length'] - 12 - pkt['captured_len'],
        base_schema=Option,
        type_name='type',
        registry=collections.defaultdict(lambda: UnknownOption, {
            Enum_OptionType.opt_endofopt: EndOfOption,
            Enum_OptionType.opt_comment: CommentOption,
            Enum_OptionType.ns_dnsname: NS_DNSNameOption,
            Enum_OptionType.ns_dnsIP4addr: NS_DNSIP4AddrOption,
            Enum_OptionType.ns_dnsIP6addr: NS_DNSIP6AddrOption,
        }),
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_BlockType', length: 'int',
                     records: 'list[NameResolutionRecord | bytes] | bytes',
                     options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...
