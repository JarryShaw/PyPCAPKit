# -*- coding: utf-8 -*-
"""PCAP-NG File Format
=========================

.. module:: pcapkit.protocols.misc.pcapng

:mod:`pcapkit.protocols.misc.pcapng` contains
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` only,
which implements extractor for PCAP-NG file format [*]_.

.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html

"""
import collections
import datetime
import decimal
import enum
import io
import operator
import sys
import time
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.const.pcapng.hash_algorithm import HashAlgorithm as Enum_HashAlgorithm
from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
from pcapkit.const.pcapng.record_type import RecordType as Enum_RecordType
from pcapkit.const.pcapng.secrets_type import SecretsType as Enum_SecretsType
from pcapkit.const.pcapng.verdict_type import VerdictType as Enum_VerdictType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.corekit.version import VersionInfo
from pcapkit.protocols.data.misc.pcapng import PCAPNG as Data_PCAPNG
from pcapkit.protocols.data.misc.pcapng import CommentOption as Data_CommentOption
from pcapkit.protocols.data.misc.pcapng import CustomBlock as Data_CustomBlock
from pcapkit.protocols.data.misc.pcapng import DecryptionSecretsBlock as Data_DecryptionSecretsBlock
from pcapkit.protocols.data.misc.pcapng import DSBSecrets as Data_DSBSecrets
from pcapkit.protocols.data.misc.pcapng import EndOfOption as Data_EndOfOption
from pcapkit.protocols.data.misc.pcapng import EndRecord as Data_EndRecord
from pcapkit.protocols.data.misc.pcapng import EnhancedPacketBlock as Data_EnhancedPacketBlock
from pcapkit.protocols.data.misc.pcapng import EPB_DropCountOption as Data_EPB_DropCountOption
from pcapkit.protocols.data.misc.pcapng import EPB_FlagsOption as Data_EPB_FlagsOption
from pcapkit.protocols.data.misc.pcapng import EPB_HashOption as Data_EPB_HashOption
from pcapkit.protocols.data.misc.pcapng import EPB_PacketIDOption as Data_EPB_PacketIDOption
from pcapkit.protocols.data.misc.pcapng import EPB_QueueOption as Data_EPB_QueueOption
from pcapkit.protocols.data.misc.pcapng import EPB_VerdictOption as Data_EPB_VerdictOption
from pcapkit.protocols.data.misc.pcapng import IF_DescriptionOption as Data_IF_DescriptionOption
from pcapkit.protocols.data.misc.pcapng import IF_EUIAddrOption as Data_IF_EUIAddrOption
from pcapkit.protocols.data.misc.pcapng import IF_FCSLenOption as Data_IF_FCSLenOption
from pcapkit.protocols.data.misc.pcapng import IF_FilterOption as Data_IF_FilterOption
from pcapkit.protocols.data.misc.pcapng import IF_HardwareOption as Data_IF_HardwareOption
from pcapkit.protocols.data.misc.pcapng import IF_IPv4AddrOption as Data_IF_IPv4AddrOption
from pcapkit.protocols.data.misc.pcapng import IF_IPv6AddrOption as Data_IF_IPv6AddrOption
from pcapkit.protocols.data.misc.pcapng import IF_MACAddrOption as Data_IF_MACAddrOption
from pcapkit.protocols.data.misc.pcapng import IF_NameOption as Data_IF_NameOption
from pcapkit.protocols.data.misc.pcapng import IF_OSOption as Data_IF_OSOption
from pcapkit.protocols.data.misc.pcapng import IF_RxSpeedOption as Data_IF_RxSpeedOption
from pcapkit.protocols.data.misc.pcapng import IF_SpeedOption as Data_IF_SpeedOption
from pcapkit.protocols.data.misc.pcapng import IF_TSOffsetOption as Data_IF_TSOffsetOption
from pcapkit.protocols.data.misc.pcapng import IF_TSResolOption as Data_IF_TSResolOption
from pcapkit.protocols.data.misc.pcapng import IF_TxSpeedOption as Data_IF_TxSpeedOption
from pcapkit.protocols.data.misc.pcapng import IF_TZoneOption as Data_IF_TZoneOption
from pcapkit.protocols.data.misc.pcapng import \
    InterfaceDescriptionBlock as Data_InterfaceDescriptionBlock
from pcapkit.protocols.data.misc.pcapng import \
    InterfaceStatisticsBlock as Data_InterfaceStatisticsBlock
from pcapkit.protocols.data.misc.pcapng import IPv4Record as Data_IPv4Record
from pcapkit.protocols.data.misc.pcapng import IPv6Record as Data_IPv6Record
from pcapkit.protocols.data.misc.pcapng import ISB_EndTimeOption as Data_ISB_EndTimeOption
from pcapkit.protocols.data.misc.pcapng import ISB_FilterAcceptOption as Data_ISB_FilterAcceptOption
from pcapkit.protocols.data.misc.pcapng import ISB_IFDropOption as Data_ISB_IFDropOption
from pcapkit.protocols.data.misc.pcapng import ISB_IFRecvOption as Data_ISB_IFRecvOption
from pcapkit.protocols.data.misc.pcapng import ISB_OSDropOption as Data_ISB_OSDropOption
from pcapkit.protocols.data.misc.pcapng import ISB_StartTimeOption as Data_ISB_StartTimeOption
from pcapkit.protocols.data.misc.pcapng import ISB_UsrDelivOption as Data_ISB_UsrDelivOption
from pcapkit.protocols.data.misc.pcapng import NameResolutionBlock as Data_NameResolutionBlock
from pcapkit.protocols.data.misc.pcapng import NameResolutionRecord as Data_NameResolutionRecord
from pcapkit.protocols.data.misc.pcapng import NS_DNSIP4AddrOption as Data_NS_DNSIP4AddrOption
from pcapkit.protocols.data.misc.pcapng import NS_DNSIP6AddrOption as Data_NS_DNSIP6AddrOption
from pcapkit.protocols.data.misc.pcapng import NS_DNSNameOption as Data_NS_DNSNameOption
from pcapkit.protocols.data.misc.pcapng import Option as Data_Option
from pcapkit.protocols.data.misc.pcapng import PacketBlock as Data_PacketBlock
from pcapkit.protocols.data.misc.pcapng import SectionHeaderBlock as Data_SectionHeaderBlock
from pcapkit.protocols.data.misc.pcapng import SimplePacketBlock as Data_SimplePacketBlock
from pcapkit.protocols.data.misc.pcapng import \
    SystemdJournalExportBlock as Data_SystemdJournalExportBlock
from pcapkit.protocols.data.misc.pcapng import TLSKeyLog as Data_TLSKeyLog
from pcapkit.protocols.data.misc.pcapng import UnknownBlock as Data_UnknownBlock
from pcapkit.protocols.data.misc.pcapng import UnknownOption as Data_UnknownOption
from pcapkit.protocols.data.misc.pcapng import UnknownRecord as Data_UnknownRecord
from pcapkit.protocols.data.misc.pcapng import UnknownSecrets as Data_UnknownSecrets
from pcapkit.protocols.data.misc.pcapng import WireGuardKeyLog as Data_WireGuardKeyLog
from pcapkit.protocols.data.misc.pcapng import ZigBeeAPSKey as Data_ZigBeeAPSKey
from pcapkit.protocols.data.misc.pcapng import ZigBeeNWKKey as Data_ZigBeeNWKKey
from pcapkit.protocols.protocol import Protocol
from pcapkit.protocols.schema.misc.pcapng import PCAPNG as Schema_PCAPNG
from pcapkit.protocols.schema.misc.pcapng import BlockType as Schema_BlockType
from pcapkit.protocols.schema.misc.pcapng import CommentOption as Schema_CommentOption
from pcapkit.protocols.schema.misc.pcapng import CustomBlock as Schema_CustomBlock
from pcapkit.protocols.schema.misc.pcapng import \
    DecryptionSecretsBlock as Schema_DecryptionSecretsBlock
from pcapkit.protocols.schema.misc.pcapng import DSBSecrets as Schema_DSBSecrets
from pcapkit.protocols.schema.misc.pcapng import EndOfOption as Schema_EndOfOption
from pcapkit.protocols.schema.misc.pcapng import EndRecord as Schema_EndRecord
from pcapkit.protocols.schema.misc.pcapng import EnhancedPacketBlock as Schema_EnhancedPacketBlock
from pcapkit.protocols.schema.misc.pcapng import EPB_DropCountOption as Schema_EPB_DropCountOption
from pcapkit.protocols.schema.misc.pcapng import EPB_FlagsOption as Schema_EPB_FlagsOption
from pcapkit.protocols.schema.misc.pcapng import EPB_HashOption as Schema_EPB_HashOption
from pcapkit.protocols.schema.misc.pcapng import EPB_PacketIDOption as Schema_EPB_PacketIDOption
from pcapkit.protocols.schema.misc.pcapng import EPB_QueueOption as Schema_EPB_QueueOption
from pcapkit.protocols.schema.misc.pcapng import EPB_VerdictOption as Schema_EPB_VerdictOption
from pcapkit.protocols.schema.misc.pcapng import IF_DescriptionOption as Schema_IF_DescriptionOption
from pcapkit.protocols.schema.misc.pcapng import IF_EUIAddrOption as Schema_IF_EUIAddrOption
from pcapkit.protocols.schema.misc.pcapng import IF_FCSLenOption as Schema_IF_FCSLenOption
from pcapkit.protocols.schema.misc.pcapng import IF_FilterOption as Schema_IF_FilterOption
from pcapkit.protocols.schema.misc.pcapng import IF_HardwareOption as Schema_IF_HardwareOption
from pcapkit.protocols.schema.misc.pcapng import IF_IPv4AddrOption as Schema_IF_IPv4AddrOption
from pcapkit.protocols.schema.misc.pcapng import IF_IPv6AddrOption as Schema_IF_IPv6AddrOption
from pcapkit.protocols.schema.misc.pcapng import IF_MACAddrOption as Schema_IF_MACAddrOption
from pcapkit.protocols.schema.misc.pcapng import IF_NameOption as Schema_IF_NameOption
from pcapkit.protocols.schema.misc.pcapng import IF_OSOption as Schema_IF_OSOption
from pcapkit.protocols.schema.misc.pcapng import IF_RxSpeedOption as Schema_IF_RxSpeedOption
from pcapkit.protocols.schema.misc.pcapng import IF_SpeedOption as Schema_IF_SpeedOption
from pcapkit.protocols.schema.misc.pcapng import IF_TSOffsetOption as Schema_IF_TSOffsetOption
from pcapkit.protocols.schema.misc.pcapng import IF_TSResolOption as Schema_IF_TSResolOption
from pcapkit.protocols.schema.misc.pcapng import IF_TxSpeedOption as Schema_IF_TxSpeedOption
from pcapkit.protocols.schema.misc.pcapng import IF_TZoneOption as Schema_IF_TZoneOption
from pcapkit.protocols.schema.misc.pcapng import \
    InterfaceDescriptionBlock as Schema_InterfaceDescriptionBlock
from pcapkit.protocols.schema.misc.pcapng import \
    InterfaceStatisticsBlock as Schema_InterfaceStatisticsBlock
from pcapkit.protocols.schema.misc.pcapng import IPv4Record as Schema_IPv4Record
from pcapkit.protocols.schema.misc.pcapng import IPv6Record as Schema_IPv6Record
from pcapkit.protocols.schema.misc.pcapng import ISB_EndTimeOption as Schema_ISB_EndTimeOption
from pcapkit.protocols.schema.misc.pcapng import \
    ISB_FilterAcceptOption as Schema_ISB_FilterAcceptOption
from pcapkit.protocols.schema.misc.pcapng import ISB_IFDropOption as Schema_ISB_IFDropOption
from pcapkit.protocols.schema.misc.pcapng import ISB_IFRecvOption as Schema_ISB_IFRecvOption
from pcapkit.protocols.schema.misc.pcapng import ISB_OSDropOption as Schema_ISB_OSDropOption
from pcapkit.protocols.schema.misc.pcapng import ISB_StartTimeOption as Schema_ISB_StartTimeOption
from pcapkit.protocols.schema.misc.pcapng import ISB_UsrDelivOption as Schema_ISB_UsrDelivOption
from pcapkit.protocols.schema.misc.pcapng import NameResolutionBlock as Schema_NameResolutionBlock
from pcapkit.protocols.schema.misc.pcapng import NameResolutionRecord as Schema_NameResolutionRecord
from pcapkit.protocols.schema.misc.pcapng import NS_DNSIP4AddrOption as Schema_NS_DNSIP4AddrOption
from pcapkit.protocols.schema.misc.pcapng import NS_DNSIP6AddrOption as Schema_NS_DNSIP6AddrOption
from pcapkit.protocols.schema.misc.pcapng import NS_DNSNameOption as Schema_NS_DNSNameOption
from pcapkit.protocols.schema.misc.pcapng import Option as Schema_Option
from pcapkit.protocols.schema.misc.pcapng import PacketBlock as Schema_PacketBlock
from pcapkit.protocols.schema.misc.pcapng import SectionHeaderBlock as Schema_SectionHeaderBlock
from pcapkit.protocols.schema.misc.pcapng import SimplePacketBlock as Schema_SimplePacketBlock
from pcapkit.protocols.schema.misc.pcapng import \
    SystemdJournalExportBlock as Schema_SystemdJournalExportBlock
from pcapkit.protocols.schema.misc.pcapng import TLSKeyLog as Schema_TLSKeyLog
from pcapkit.protocols.schema.misc.pcapng import UnknownBlock as Schema_UnknownBlock
from pcapkit.protocols.schema.misc.pcapng import UnknownOption as Schema_UnknownOption
from pcapkit.protocols.schema.misc.pcapng import UnknownRecord as Schema_UnknownRecord
from pcapkit.protocols.schema.misc.pcapng import UnknownSecrets as Schema_UnknownSecrets
from pcapkit.protocols.schema.misc.pcapng import WireGuardKeyLog as Schema_WireGuardKeyLog
from pcapkit.protocols.schema.misc.pcapng import ZigBeeAPSKey as Schema_ZigBeeAPSKey
from pcapkit.protocols.schema.misc.pcapng import ZigBeeNWKKey as Schema_ZigBeeNWKKey
from pcapkit.utilities.compat import StrEnum
from pcapkit.utilities.exceptions import EndianError, FileError, UnsupportedCall
from pcapkit.utilities.warnings import RegistryWarning, warn

__all__ = ['PCAPNG']

if TYPE_CHECKING:
    from typing import Any, Callable, DefaultDict, Optional

    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    Option = OrderedMultiDict[Enum_OptionType, Data_Option]

    BlockParser = Callable[[Schema_BlockType, NamedArg(Schema_PCAPNG, 'header')], Data_PCAPNG]
    BlockConstructor = Callable[[Enum_BlockType, DefaultArg(Optional[Data_PCAPNG]),
                                 KwArg(Any)], Schema_BlockType]

    OptionParser = Callable[[Schema_Option, NamedArg(Option, 'options')], Data_Option]
    OptionConstructor = Callable[[Enum_OptionType, DefaultArg(Optional[Data_Option]),
                                  KwArg(Any)], Schema_Option]

    SecretsParser = Callable[[Schema_DSBSecrets, NamedArg(Schema_DecryptionSecretsBlock, 'dsb')],
                             Data_DSBSecrets]
    SecretsConstructor = Callable[[Enum_SecretsType, DefaultArg(Optional[Data_DSBSecrets]),
                                   KwArg(Any)], Schema_DSBSecrets]

    RecordParser = Callable[[Schema_NameResolutionRecord, NamedArg(Schema_NameResolutionBlock, 'nrb')],
                            Data_NameResolutionRecord]
    RecordConstructor = Callable[[Enum_RecordType, DefaultArg(Optional[Data_NameResolutionRecord]),
                                  KwArg(Any)], Schema_NameResolutionRecord]


class PacketDirection(enum.IntEnum):
    """Packet direction for ``epb_flags`` options."""

    #: Information not available.
    UNKNOWN = 0b00
    #: Inbound packet.
    INBOUND = 0b01
    #: Outbound packet.
    OUTBOUND = 0b10


class PacketReception(enum.IntEnum):
    """Reception type for ``epb_flags`` options."""

    #: Not specified.
    UNKNOWN = 0b000
    #: Unicast.
    UNICAST = 0b001
    #: Multicast.
    MULTICAST = 0b010
    #: Broadcast.
    BROADCAST = 0b011
    #: Promiscuous.
    PROMISCUOUS = 0b100


class TLSKeyLabel(StrEnum):
    """TLS key log label."""

    RSA = 'RSA'
    CLIENT_RANDOM = 'CLIENT_RANDOM'
    CLIENT_EARLY_TRAFFIC_SECRET = 'CLIENT_EARLY_TRAFFIC_SECRET'  # nosec B105
    CLIENT_HANDSHAKE_TRAFFIC_SECRET = 'CLIENT_HANDSHAKE_TRAFFIC_SECRET'  # nosec B105
    SERVER_HANDSHAKE_TRAFFIC_SECRET = 'SERVER_HANDSHAKE_TRAFFIC_SECRET'  # nosec B105
    CLIENT_TRAFFIC_SECRET_0 = 'CLIENT_TRAFFIC_SECRET_0'  # nosec B105
    SERVER_TRAFFIC_SECRET_0 = 'SERVER_TRAFFIC_SECRET_0'  # nosec B105
    EARLY_EXPORTER_SECRET = 'EARLY_EXPORTER_SECRET'  # nosec B105
    EXPORTER_SECRET = 'EXPORTER_SECRET'  # nosec B105


class WireGuardKeyLabel(StrEnum):
    """WireGuard key log label."""

    LOCAL_STATIC_PRIVATE_KEY = 'LOCAL_STATIC_PRIVATE_KEY'
    REMOTE_STATIC_PUBLIC_KEY = 'REMOTE_STATIC_PUBLIC_KEY'
    LOCAL_EPHEMERAL_PRIVATE_KEY = 'LOCAL_EPHEMERAL_PRIVATE_KEY'
    PRESHARED_KEY = 'PRESHARED_KEY'


class PCAPNG(Protocol[Data_PCAPNG, Schema_PCAPNG],
             schema=Schema_PCAPNG, data=Data_PCAPNG):
    """PCAP-NG file block extractor.

    The class currently supports parsing of the following protocols, which are
    registered in the :attr:`self.__proto__ <pcapkit.protocols.misc.pcap.frame.Frame.__proto__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Index
         - Protocol
       * - :attr:`pcapkit.const.reg.linktype.LinkType.ETHERNET`
         - :class:`pcapkit.protocols.link.ethernet.Ethernet`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.IPV4`
         - :class:`pcapkit.protocols.internet.ipv4.IPv4`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.IPV6`
         - :class:`pcapkit.protocols.internet.ipv6.IPv6`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[Enum_LinkType, tuple[str, str]]: Protocol index mapping for
    #: decoding next layer, c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    #: The values should be a tuple representing the module name and class name.
    __proto__ = collections.defaultdict(
        lambda: ('pcapkit.protocols.misc.raw', 'Raw'),
        {
            Enum_LinkType.ETHERNET: ('pcapkit.protocols.link', 'Ethernet'),
            Enum_LinkType.IPV4:     ('pcapkit.protocols.internet', 'IPv4'),
            Enum_LinkType.IPV6:     ('pcapkit.protocols.internet', 'IPv6'),
        },
    )  # type: DefaultDict[Enum_LinkType | int, tuple[str, str]]

    #: DefaultDict[Enum_BlockType, str | tuple[BlockParser, BlockConstructor]]:
    #: Block type to method mapping. Method names are expected to be referred
    #: to the class by ``_read_pcapng_${name}`` and/or ``_make_pcapng_${name}``,
    #: and if such name not found, the value should then be a method that can
    #: parse the block by itself.
    __block__ = collections.defaultdict(
        lambda: 'unknown',
        {
            Enum_BlockType.Section_Header_Block: 'shb',
            Enum_BlockType.Interface_Description_Block: 'idb',
            Enum_BlockType.Enhanced_Packet_Block: 'epb',
            Enum_BlockType.Simple_Packet_Block: 'spb',
            Enum_BlockType.Name_Resolution_Block: 'nrb',
            Enum_BlockType.Interface_Statistics_Block: 'isb',
            Enum_BlockType.systemd_Journal_Export_Block: 'systemd',
            Enum_BlockType.Decryption_Secrets_Block: 'dsb',
            Enum_BlockType.Custom_Block_that_rewriters_can_copy_into_new_files: 'custom',
            Enum_BlockType.Custom_Block_that_rewriters_should_not_copy_into_new_files: 'custom',
            Enum_BlockType.Packet_Block: 'packet',
        },
    )  # type: DefaultDict[Enum_BlockType | int, str | tuple[BlockParser, BlockConstructor]]

    #: DefaultDict[Enum_OptionType, str | tuple[OptionParser, OptionConstructor]]:
    #: Block option type to method mapping. Method names are expected to be
    #: referred to the class by ``_read_option_${name}`` and/or ``_make_option_${name}``,
    #: and if such name not found, the value should then be a method that can
    #: parse the option by itself.
    __option__ = collections.defaultdict(
        lambda: 'unknown',
        {
            Enum_OptionType.opt_endofopt: 'endofopt',
            Enum_OptionType.opt_comment: 'comment',
            Enum_OptionType.if_name: 'if_name',
            Enum_OptionType.if_description: 'if_description',
            Enum_OptionType.if_IPv4addr: 'if_ipv4',
            Enum_OptionType.if_IPv6addr: 'if_ipv6',
            Enum_OptionType.if_MACaddr: 'if_mac',
            Enum_OptionType.if_EUIaddr: 'if_eui',
            Enum_OptionType.if_speed: 'if_speed',
            Enum_OptionType.if_tsresol: 'if_tsresol',
            Enum_OptionType.if_tzone: 'if_tzone',
            Enum_OptionType.if_filter: 'if_filter',
            Enum_OptionType.if_os: 'if_os',
            Enum_OptionType.if_fcslen: 'if_fcslen',
            Enum_OptionType.if_tsoffset: 'if_tsoffset',
            Enum_OptionType.if_hardware: 'if_hardware',
            Enum_OptionType.if_txspeed: 'if_txspeed',
            Enum_OptionType.if_rxspeed: 'if_rxspeed',
            Enum_OptionType.epb_flags: 'epb_flags',
            Enum_OptionType.epb_hash: 'epb_hash',
            Enum_OptionType.epb_dropcount: 'epb_dropcount',
            Enum_OptionType.epb_packetid: 'epb_packetid',
            Enum_OptionType.epb_queue: 'epb_queue',
            Enum_OptionType.epb_verdict: 'epb_verdict',
            Enum_OptionType.ns_dnsname: 'ns_dnsname',
            Enum_OptionType.ns_dnsIP4addr: 'ns_dnsipv4',
            Enum_OptionType.ns_dnsIP6addr: 'ns_dnsipv6',
            Enum_OptionType.isb_starttime: 'isb_starttime',
            Enum_OptionType.isb_endtime: 'isb_endtime',
            Enum_OptionType.isb_ifrecv: 'isb_ifrecv',
            Enum_OptionType.isb_ifdrop: 'isb_ifdrop',
            Enum_OptionType.isb_filteraccept: 'isb_filteraccept',
            Enum_OptionType.isb_osdrop: 'isb_osdrop',
            Enum_OptionType.isb_usrdeliv: 'isb_usrdeliv',
            Enum_OptionType.pack_flags: 'epb_flags',
            Enum_OptionType.pack_hash: 'epb_hash',
        },
    )  # type: DefaultDict[Enum_OptionType | int, str | tuple[OptionParser, OptionConstructor]]

    #: DefaultDict[Enum_SecretsType, str | tuple[SecretsParser, SecretsConstructor]]:
    #: Decryption secrets type to method mapping. Method names are expected to
    #: be referred to the class by ``_read_secrets_${name}`` and/or ``_make_secrets_${name}``,
    #: and if such name not found, the value should then be a method that can
    #: parse the decryption secrets by itself.
    __secrets__ = collections.defaultdict(
        lambda: 'unknown',
        {
            Enum_SecretsType.TLS_Key_Log: 'tls',
            Enum_SecretsType.WireGuard_Key_Log: 'wireguard',
            Enum_SecretsType.ZigBee_NWK_Key_Log: 'zigbee_nwk',
            Enum_SecretsType.ZigBee_APS_Key_Log: 'zigbee_aps',
        },
    )  # type: DefaultDict[Enum_SecretsType | int, str | tuple[SecretsParser, SecretsConstructor]]

    #: DefaultDict[Enum_RecordType, str | tuple[RecordParser, RecordConstructor]]:
    #: Name record type to method mapping. Method names are expected to be
    #: referred to the class by ``_read_record_${name}`` and/or ``_make_record_${name}``,
    #: and if such name not found, the value should then be a method that can
    #: parse the name record by itself.
    __record__ = collections.defaultdict(
        lambda: 'unknown',
        {
            Enum_RecordType.nrb_record_end: 'end',
            Enum_RecordType.nrb_record_ipv4: 'ipv4',
            Enum_RecordType.nrb_record_ipv6: 'ipv6',
        },
    )  # type: DefaultDict[Enum_RecordType | int, str | tuple[RecordParser, RecordConstructor]]
