from datetime import datetime as dt_type, timezone as dt_timezone
from decimal import Decimal
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.const.pcapng.filter_type import FilterType as Enum_FilterType
from pcapkit.const.pcapng.hash_algorithm import HashAlgorithm as Enum_HashAlgorithm
from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
from pcapkit.const.pcapng.record_type import RecordType as Enum_RecordType
from pcapkit.const.pcapng.secrets_type import SecretsType as Enum_SecretsType
from pcapkit.const.pcapng.verdict_type import VerdictType as Enum_VerdictType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
from pcapkit.corekit.version import VersionInfo
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.misc.pcapng import PacketDirection, PacketReception, TLSKeyLabel, WireGuardKeyLabel
from typing_extensions import Literal

class PCAPNG(Data):
    type: Enum_BlockType
    length: int

class UnknownBlock(PCAPNG):
    body: bytes
    def __init__(self, type: Enum_BlockType, length: int, body: bytes) -> None: ...

class Option(Data):
    type: Enum_OptionType
    length: int

class UnknownOption(Option):
    data: bytes
    def __init__(self, type: Enum_OptionType, length: int, data: bytes) -> None: ...

class EndOfOption(Option):
    def __init__(self, type: Enum_OptionType, length: int) -> None: ...

class CommentOption(Option):
    comment: str
    def __init__(self, type: Enum_OptionType, length: int, comment: str) -> None: ...

class CustomOption(Option):
    pen: int
    data: bytes
    def __init__(self, type: Enum_OptionType, length: int, pen: int, data: bytes) -> None: ...

class SectionHeaderBlock(PCAPNG):
    byteorder: Literal['big', 'little']
    version: VersionInfo
    section_length: int
    options: OrderedMultiDict[Enum_OptionType, Option]
    def __init__(self, type: Enum_BlockType, length: int, byteorder: Literal['big', 'little'], version: VersionInfo, section_length: int, options: OrderedMultiDict[Enum_OptionType, Option]) -> None: ...

class IF_NameOption(Option):
    name: str
    def __init__(self, type: Enum_OptionType, length: int, name: str) -> None: ...

class IF_DescriptionOption(Option):
    description: str

class IF_IPv4AddrOption(Option):
    interface: IPv4Interface
    def __init__(self, type: Enum_OptionType, length: int, interface: IPv4Interface) -> None: ...

class IF_IPv6AddrOption(Option):
    interface: IPv6Interface
    def __init__(self, type: Enum_OptionType, length: int, interface: IPv6Interface) -> None: ...

class IF_MACAddrOption(Option):
    interface: str
    def __init__(self, type: Enum_OptionType, length: int, interface: str) -> None: ...

class IF_EUIAddrOption(Option):
    interface: str
    def __init__(self, type: Enum_OptionType, length: int, interface: str) -> None: ...

class IF_SpeedOption(Option):
    speed: int
    def __init__(self, type: Enum_OptionType, length: int, speed: int) -> None: ...

class IF_TSResolOption(Option):
    resolution: int
    def __init__(self, type: Enum_OptionType, length: int, resolution: int) -> None: ...

class IF_TZoneOption(Option):
    timezone: dt_timezone
    def __init__(self, type: Enum_OptionType, length: int, timezone: dt_timezone) -> None: ...

class IF_FilterOption(Option):
    code: Enum_FilterType
    expression: bytes
    def __init__(self, type: Enum_OptionType, length: int, code: Enum_FilterType, expression: bytes) -> None: ...

class IF_OSOption(Option):
    os: str
    def __init__(self, type: Enum_OptionType, length: int, os: str) -> None: ...

class IF_FCSLenOption(Option):
    fcs_length: int
    def __init__(self, type: Enum_OptionType, length: int, fcs_length: int) -> None: ...

class IF_TSOffsetOption(Option):
    offset: int
    def __init__(self, type: Enum_OptionType, length: int, offset: int) -> None: ...

class IF_HardwareOption(Option):
    hardware: str
    def __init__(self, type: Enum_OptionType, length: int, hardware: str) -> None: ...

class IF_TxSpeedOption(Option):
    speed: int
    def __init__(self, type: Enum_OptionType, length: int, speed: int) -> None: ...

class IF_RxSpeedOption(Option):
    speed: int
    def __init__(self, type: Enum_OptionType, length: int, speed: int) -> None: ...

class InterfaceDescriptionBlock(PCAPNG):
    linktype: Enum_LinkType
    snaplen: int
    options: OrderedMultiDict[Enum_OptionType, Option]
    def __init__(self, type: Enum_BlockType, length: int, linktype: Enum_LinkType, snaplen: int, options: OrderedMultiDict[Enum_OptionType, Option]) -> None: ...

class EPB_FlagsOption(Option):
    direction: PacketDirection
    reception: PacketReception
    fcs_len: int
    crc_error: bool
    too_long: bool
    too_short: bool
    gap_error: bool
    unaligned_error: bool
    delimiter_error: bool
    preamble_error: bool
    symbol_error: bool
    def __init__(self, type: Enum_OptionType, length: int, direction: PacketDirection, reception: PacketReception, fcs_len: int, crc_error: bool, too_long: bool, too_short: bool, gap_error: bool, unaligned_error: bool, delimiter_error: bool, preamble_error: bool, symbol_error: bool) -> None: ...

class EPB_HashOption(Option):
    algorithm: Enum_HashAlgorithm
    hash: bytes
    def __init__(self, type: Enum_OptionType, length: int, algorithm: Enum_HashAlgorithm, hash: bytes) -> None: ...

class EPB_DropCountOption(Option):
    drop_count: int
    def __init__(self, type: Enum_OptionType, length: int, drop_count: int) -> None: ...

class EPB_PacketIDOption(Option):
    packet_id: int
    def __init__(self, type: Enum_OptionType, length: int, packet_id: int) -> None: ...

class EPB_QueueOption(Option):
    queue_id: int
    def __init__(self, type: Enum_OptionType, length: int, queue_id: int) -> None: ...

class EPB_VerdictOption(Option):
    verdict: Enum_VerdictType
    value: bytes
    def __init__(self, type: Enum_OptionType, length: int, verdict: Enum_VerdictType, value: bytes) -> None: ...

class EnhancedPacketBlock(PCAPNG):
    section_number: int
    number: int
    interface_id: int
    timestamp: dt_type
    timestamp_epoch: Decimal
    captured_len: int
    original_len: int
    options: OrderedMultiDict[Enum_OptionType, Option]
    protocols: str
    def __init__(self, type: Enum_BlockType, length: int, section_number: int, number: int, interface_id: int, timestamp: dt_type, timestamp_epoch: Decimal, captured_len: int, original_len: int, options: OrderedMultiDict[Enum_OptionType, Option]) -> None: ...

class SimplePacketBlock(PCAPNG):
    section_number: int
    number: int
    original_len: int
    captured_len: int
    def __post_init__(self) -> None: ...
    protocols: str
    interface_id: int
    timestamp: dt_type
    timestamp_epoch: Decimal
    def __init__(self, section_number: int, number: int, type: Enum_BlockType, length: int, original_len: int, captured_len: int) -> None: ...

class NameResolutionRecord(Data):
    type: Enum_RecordType
    length: int

class UnknownRecord(NameResolutionRecord):
    data: bytes
    def __init__(self, type: Enum_RecordType, length: int, data: bytes) -> None: ...

class EndRecord(NameResolutionRecord):
    def __init__(self, type: Enum_RecordType, length: int) -> None: ...

class IPv4Record(NameResolutionRecord):
    ip: IPv4Address
    records: tuple[str, ...]
    def __init__(self, type: Enum_RecordType, length: int, ip: IPv4Address, records: tuple[str, ...]) -> None: ...

class IPv6Record(NameResolutionRecord):
    ip: IPv6Address
    records: tuple[str, ...]
    def __init__(self, type: Enum_RecordType, length: int, ip: IPv6Address, records: tuple[str, ...]) -> None: ...

class NS_DNSNameOption(Option):
    name: str
    def __init__(self, type: Enum_OptionType, length: int, name: str) -> None: ...

class NS_DNSIP4AddrOption(Option):
    ip: IPv4Address
    def __init__(self, type: Enum_OptionType, length: int, ip: IPv4Address) -> None: ...

class NS_DNSIP6AddrOption(Option):
    ip: IPv6Address
    def __init__(self, type: Enum_OptionType, length: int, ip: IPv6Address) -> None: ...

class NameResolutionBlock(PCAPNG):
    records: OrderedMultiDict[Enum_RecordType, NameResolutionRecord]
    options: OrderedMultiDict[Enum_OptionType, Option]
    def __post_init__(self) -> None: ...
    mapping: MultiDict[IPv4Address | IPv6Address, str]
    reverse_mapping: MultiDict[str, IPv4Address | IPv6Address]
    def __init__(self, type: Enum_BlockType, length: int, records: OrderedMultiDict[Enum_RecordType, NameResolutionRecord], options: OrderedMultiDict[Enum_OptionType, Option]) -> None: ...

class ISB_StartTimeOption(Option):
    timestamp: dt_type
    timestamp_epoch: Decimal
    def __init__(self, type: Enum_OptionType, length: int, timestamp: dt_type, timestamp_epoch: Decimal) -> None: ...

class ISB_EndTimeOption(Option):
    timestamp: dt_type
    timestamp_epoch: Decimal
    def __init__(self, type: Enum_OptionType, length: int, timestamp: dt_type, timestamp_epoch: Decimal) -> None: ...

class ISB_IFRecvOption(Option):
    packets: int
    def __init__(self, type: Enum_OptionType, length: int, packets: int) -> None: ...

class ISB_IFDropOption(Option):
    packets: int
    def __init__(self, type: Enum_OptionType, length: int, packets: int) -> None: ...

class ISB_FilterAcceptOption(Option):
    packets: int
    def __init__(self, type: Enum_OptionType, length: int, packets: int) -> None: ...

class ISB_OSDropOption(Option):
    packets: int
    def __init__(self, type: Enum_OptionType, length: int, packets: int) -> None: ...

class ISB_UsrDelivOption(Option):
    packets: int
    def __init__(self, type: Enum_OptionType, length: int, packets: int) -> None: ...

class InterfaceStatisticsBlock(PCAPNG):
    interface_id: int
    timestamp: dt_type
    timestamp_epoch: Decimal
    options: OrderedMultiDict[Enum_OptionType, Option]
    def __init__(self, type: Enum_BlockType, length: int, interface_id: int, timestamp: dt_type, timestamp_epoch: Decimal, options: OrderedMultiDict[Enum_OptionType, Option]) -> None: ...

class SystemdJournalExportBlock(PCAPNG):
    data: tuple[OrderedMultiDict[str, str | bytes], ...]
    def __init__(self, type: Enum_BlockType, length: int, data: tuple[OrderedMultiDict[str, str | bytes], ...]) -> None: ...

class DSBSecrets(Data): ...

class UnknownSecrets(DSBSecrets):
    data: bytes
    def __init__(self, data: bytes) -> None: ...

class TLSKeyLog(DSBSecrets):
    entries: dict[TLSKeyLabel, OrderedMultiDict[bytes, bytes]]
    def __init__(self, entries: dict[TLSKeyLabel, OrderedMultiDict[bytes, bytes]]) -> None: ...

class WireGuardKeyLog(DSBSecrets):
    entries: OrderedMultiDict[WireGuardKeyLabel, bytes]
    def __init__(self, entries: OrderedMultiDict[WireGuardKeyLabel, bytes]) -> None: ...

class ZigBeeNWKKey(DSBSecrets):
    nwk_key: bytes
    pan_id: int
    def __init__(self, nwk_key: bytes, pan_id: int) -> None: ...

class ZigBeeAPSKey(DSBSecrets):
    aps_key: bytes
    pan_id: int
    short_address: int
    def __init__(self, aps_key: bytes, pan_id: int, short_address: int) -> None: ...

class DecryptionSecretsBlock(PCAPNG):
    secrets_type: Enum_SecretsType
    secrets_length: int
    secrets_data: DSBSecrets
    options: OrderedMultiDict[Enum_OptionType, Option]
    def __init__(self, type: Enum_BlockType, length: int, secrets_type: Enum_SecretsType, secrets_length: int, secrets_data: DSBSecrets, options: OrderedMultiDict[Enum_OptionType, Option]) -> None: ...

class CustomBlock(PCAPNG):
    pen: int
    data: bytes
    def __init__(self, type: Enum_BlockType, length: int, pen: int, data: bytes) -> None: ...

class PACK_FlagsOption(Option):
    direction: PacketDirection
    reception: PacketReception
    fcs_len: int
    crc_error: bool
    too_long: bool
    too_short: bool
    gap_error: bool
    unaligned_error: bool
    delimiter_error: bool
    preamble_error: bool
    symbol_error: bool
    def __init__(self, type: Enum_OptionType, length: int, direction: PacketDirection, reception: PacketReception, fcs_len: int, crc_error: bool, too_long: bool, too_short: bool, gap_error: bool, unaligned_error: bool, delimiter_error: bool, preamble_error: bool, symbol_error: bool) -> None: ...

class PACK_HashOption(Option):
    algorithm: Enum_HashAlgorithm
    hash: bytes
    def __init__(self, type: Enum_OptionType, length: int, algorithm: Enum_HashAlgorithm, hash: bytes) -> None: ...

class PacketBlock(PCAPNG):
    section_number: int
    number: int
    interface_id: int
    drop_count: int
    timestamp: dt_type
    timestamp_epoch: Decimal
    captured_len: int
    original_len: int
    options: OrderedMultiDict[Enum_OptionType, Option]
    protocols: str
    def __init__(self, type: Enum_BlockType, length: int, section_number: int, number: int, interface_id: int, drop_count: int, timestamp: dt_type, timestamp_epoch: Decimal, captured_length: int, original_length: int, options: OrderedMultiDict[Enum_OptionType, Option]) -> None: ...
