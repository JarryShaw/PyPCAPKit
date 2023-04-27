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
from pcapkit.utilities.exceptions import EndianError, FileError, ProtocolError, UnsupportedCall
from pcapkit.utilities.warnings import RegistryWarning, warn

__all__ = ['PCAPNG']

if TYPE_CHECKING:
    from decimal import Decimal
    from typing import IO, Any, Callable, DefaultDict, Optional, Type, Union
    from enum import IntEnum as StdlibEnum
    from aenum import IntEnum as AenumEnum

    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.foundation.engines.pcapng import Context
    from pcapkit.protocols.schema.schema import Schema

    Packet = Union[Data_EnhancedPacketBlock, Data_SimplePacketBlock, Data_PacketBlock]
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
    registered in the :attr:`self.__proto__ <pcapkit.protocols.misc.pcapng.PCAPNG.__proto__>`
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

    The class currently supports parsing of the following block types, which
    are registered in the :attr:`self.__block__ <pcapkit.protocols.misc.pcapng.PCAPNG.__block__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Block Type
         - Block Parser
         - Block Constructor
       * - :attr:`~pcapkit.const.pcapng.block_type.BlockType.Section_Header_Block`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_block_shb`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_block_shb`
       * - :attr:`~pcapkit.const.pcapng.block_type.BlockType.Interface_Description_Block`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_block_idb`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_block_idb`
       * - :attr:`~pcapkit.const.pcapng.block_type.BlockType.Enhanced_Packet_Block`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_block_epb`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_block_epb`
       * - :attr:`~pcapkit.const.pcapng.block_type.BlockType.Simple_Packet_Block`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_block_spb`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_block_spb`
       * - :attr:`~pcapkit.const.pcapng.block_type.BlockType.Name_Resolution_Block`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_block_nrb`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_block_nrb`
       * - :attr:`~pcapkit.const.pcapng.block_type.BlockType.Interface_Statistics_Block`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_block_isb`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_block_isb`
       * - :attr:`~pcapkit.const.pcapng.block_type.BlockType.systemd_Journal_Export_Block`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_block_systemd`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_block_systemd`
       * - :attr:`~pcapkit.const.pcapng.block_type.BlockType.Decryption_Secrets_Block`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_block_dsb`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_block_dsb`
       * - :attr:`~pcapkit.const.pcapng.block_type.BlockType.Custom_Block_that_rewriters_can_copy_into_new_files`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_block_cb`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_block_cb`
       * - :attr:`~pcapkit.const.pcapng.block_type.BlockType.Custom_Block_that_rewriters_should_not_copy_into_new_files`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_block_cb`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_block_cb`
       * - :attr:`~pcapkit.const.pcapng.block_type.BlockType.Packet_Block`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_block_packet`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_block_packet`

    The class currently supports parsing of the following option types, which
    are registered in the :attr:`self.__option__ <pcapkit.protocols.misc.pcapng.PCAPNG.__option__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Option Type
         - Option Parser
         - Option Constructor
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.opt_endofopt`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_endofopt`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_endofopt`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.opt_comment`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_comment`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_comment`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_name`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_name`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_name`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_description`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_description`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_description`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_IPv4addr`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_ipv4`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_ipv4`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_IPv6addr`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_ipv6`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_ipv6`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_MACaddr`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_mac`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_mac`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_EUIaddr`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_eui`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_eui`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_speed`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_speed`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_speed`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_tsresol`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_tsresol`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_tsresol`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_tzone`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_tzone`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_tzone`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_filter`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_filter`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_filter`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_os`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_os`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_os`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_fcslen`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_fcslen`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_fcslen`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_tsoffset`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_tsoffset`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_tsoffset`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_hardware`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_hardware`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_hardware`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_txspeed`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_txspeed`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_txspeed`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.if_rxspeed`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_if_rxspeed`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_if_rxspeed`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.epb_flags`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_epb_flags`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_epb_flags`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.epb_hash`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_epb_hash`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_epb_hash`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.epb_dropcount`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_epb_dropcount`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_epb_dropcount`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.epb_packetid`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_epb_packetid`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_epb_packetid`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.epb_queue`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_epb_queue`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_epb_queue`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.epb_verdict`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_epb_verdict`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_epb_verdict`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.ds_dnsname`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_ds_dnsname`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_ds_dnsname`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.ns_dnsIP4addr`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_ns_dnsipv4`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_ns_dnsipv4`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.ns_dnsIP6addr`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_ns_dnsipv6`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_ns_dnsipv6`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.isb_starttime`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_isb_starttime`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_isb_starttime`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.isb_endtime`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_isb_endtime`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_isb_endtime`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.isb_ifrecv`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_isb_ifrecv`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_isb_ifrecv`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.isb_ifdrop`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_isb_ifdrop`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_isb_ifdrop`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.isb_filteraccept`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_isb_filteraccept`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_isb_filteraccept`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.isb_osdrop`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_isb_osdrop`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_isb_osdrop`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.isb_usrdeliv`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_isb_usrdeliv`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_isb_usrdeliv`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.pack_flags`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_epb_flags`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_epb_flags`
       * - :attr:`~pcapkit.const.pcapng.option_type.OptionType.pack_hash`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_option_epb_hash`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_option_epb_hash`

    The class currently supports parsing of the following name resolution
    record types, which are registered in the :attr:`self.__record__ <pcapkit.protocols.misc.pcapng.PCAPNG.__record__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Record Type
         - Record Parser
         - Record Constructor
       * - :attr:`~pcapkit.const.pcapng.record_type.RecordType.nrb_record_end`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_record_end`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_record_end`
       * - :attr:`~pcapkit.const.pcapng.record_type.RecordType.nrb_record_ipv4`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_record_ipv4`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_record_ipv4`
       * - :attr:`~pcapkit.const.pcapng.record_type.RecordType.nrb_record_ipv6`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_record_ipv6`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_record_ipv6`

    The class currently supports parsing of the following decryption secrets
    types, which are registered in the :attr:`self.__secrets__ <pcapkit.protocols.misc.pcapng.PCAPNG.__secrets__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Secrets Type
         - Secrets Parser
         - Secrets Constructor
       * - :attr:`~pcapkit.const.pcapng.secrets_type.SecretsType.TLS_Key_Log`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_secrets_tls`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_secrets_tls`
       * - :attr:`~pcapkit.const.pcapng.secrets_type.SecretsType.WireGuard_Key_Log`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_secrets_wireguard`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_secrets_wireguard`
       * - :attr:`~pcapkit.const.pcapng.secrets_type.SecretsType.ZigBee_NWK_Key_Log`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_secrets_zigbee_nwk`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_secrets_zigbee_nwk`
       * - :attr:`~pcapkit.const.pcapng.secrets_type.SecretsType.ZigBee_APS_Key_Log`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._read_secrets_zigbee_aps`
         - :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG._make_secrets_zigbee_aps`

    """

    PACKET_TYPES = (Enum_BlockType.Enhanced_Packet_Block,
                    Enum_BlockType.Simple_Packet_Block,
                    Enum_BlockType.Packet_Block)

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
    #: to the class by ``_read_block_${name}`` and/or ``_make_block_${name}``,
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
            Enum_BlockType.Custom_Block_that_rewriters_can_copy_into_new_files: 'cb',
            Enum_BlockType.Custom_Block_that_rewriters_should_not_copy_into_new_files: 'cb',
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

    #: DefaultDict[Enum_RecordType, str | tuple[RecordParser, RecordConstructor]]:
    #: Name resolution record type to method mapping. Method names are expected
    #: to be referred to the class by ``_read_record_${name}`` and/or ``_make_record_${name}``,
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

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'str':
        """Name of corresponding protocol."""
        if self._info.type not in self.PACKET_TYPES:
            return f'PCAP-NG {self._info.type!r}'
        return f'Frame {self._fnum}'

    @property
    def length(self) -> 'int':
        """Header length of corresponding protocol."""
        return self._info.length

    @property
    def context(self) -> 'Context':
        """Context of current PCAP-NG block."""
        return self._ctx

    @property
    def nanosecond(self) -> 'bool':
        """Whether the timestamp is in nanosecond."""
        if self._info.type not in self.PACKET_TYPES:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'nanosecond'")

        info = cast('Packet', self._info)
        options = self._ctx.interfaces[info.interface_id].options
        tsresol = cast('Optional[Data_IF_TSResolOption]',
                       options.get(Enum_OptionType.if_tsresol))  # type: ignore[call-overload]
        if tsresol is None:
            return False
        return tsresol.resolution > 1_000_000

    @property
    def linktype(self) -> 'Enum_LinkType':
        """Data link layer protocol type.

        Raises:
            UnsupportedCall: If current block is not a valid packet block, i.e.,
                EPB, ISB or obsolete Packet Block.

        """
        if self._info.type not in self.PACKET_TYPES:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'linktype'")

        info = cast('Packet', self._info)
        return self._ctx.interfaces[info.interface_id].linktype

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register(cls, code: 'Enum_LinkType', module: 'str', class_: 'str') -> 'None':  # type: ignore[override]
        r"""Register a new protocol class.

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{module}.{class_}``.

        Arguments:
            code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
            module: module name
            class\_: class name

        """
        if code in cls.__proto__:
            warn(f'protocol {code} already registered, overwriting', RegistryWarning)
        cls.__proto__[code] = (module, class_)

    def index(self, name: 'str | Protocol | Type[Protocol]') -> 'int':
        """Call :meth:`ProtoChain.index <pcapkit.corekit.protochain.ProtoChain.index>`.

        Args:
            name: ``name`` to be searched

        Returns:
            First index of ``name``.

        Raises:
            IndexNotFound: if ``name`` is not present

        """
        return self._protos.index(name)

    def pack(self, **kwargs: 'Any') -> 'bytes':
        """Pack (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Notes:
            We used a special keyword argument ``__packet__`` to pass the
            global packet data to underlying methods. This is useful when
            the packet data is not available in the current instance.

        """
        self.__header__ = self.make(**kwargs)
        packet = kwargs.get('__packet__', {})  # packet data

        if self._ctx is not None:
            packet['byteorder'] = self._ctx.section.byteorder
        return self.__header__.pack(packet)

    def unpack(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_PCAPNG':
        """Unpack (parse) packet data.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Notes:
            We used a special keyword argument ``__packet__`` to pass the
            global packet data to underlying methods. This is useful when
            the packet data is not available in the current instance.

        """
        if cast('Optional[Schema_PCAPNG]', self.__header__) is None:
            packet = kwargs.get('__packet__', {})  # packet data

            if self._ctx is not None:
                packet['bytesorder'] = self._ctx.section.byteorder
            self.__header__ = cast('Schema_PCAPNG', self.__schema__.unpack(self._file, length, packet))  # type: ignore[call-arg,misc]
        return self.read(length, **kwargs)

    def read(self, length: 'Optional[int]' = None, *, _read: 'bool' = True,
             _seek_set: 'int' = 0, **kwargs: 'Any') -> 'Data_PCAPNG':
        r"""Read PCAP-NG file blocks.

        Structure of PCAP-NG file blocks:

        .. code-block:: text
                                  1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           0 |                          Block Type                           |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           4 |                      Block Total Length                       |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           8 /                          Block Body                           /
             /              variable length, padded to 32 bits               /
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                      Block Total Length                       |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of data to be read.
            \_read: If the class is called in a parsing scenario.
            \_seek_set: File offset before reading.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        schema = self.__header__

        if schema.block.length < 12 or schema.block.length % 4 != 0:
            raise ProtocolError(f'PCAP-NG: [Block {schema.type}] invalid length: {schema.block.length}')

        name = self.__block__[schema.type]
        if isinstance(name, str):
            meth_name = f'_read_block_{name}'
            meth = cast('BlockParser',
                        getattr(self, meth_name, self._read_block_unknown))
        else:
            meth = name[0]
        block = meth(schema.block, header=schema)

        if not _read:
            # move backward to the beginning of the packet
            self._file.seek(0, io.SEEK_SET)
        else:
            # NOTE: We create a copy of the block data here for parsing
            # scenarios to keep the original packet data intact.
            seek_cur = self._file.tell()

            # move backward to the beginning of the block
            self._file.seek(_seek_set, io.SEEK_SET)

            #: bytes: Raw block data.
            self._data = self._read_fileng(schema.block.length)

            # move backward to the beginning of next block
            self._file.seek(seek_cur, io.SEEK_SET)

            #: io.BytesIO: Source packet stream.
            self._file = io.BytesIO(self._data)

        return block

    def make(self,
             type: 'Enum_BlockType | StdlibEnum | AenumEnum | str | int' = Enum_BlockType.Simple_Packet_Block,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             block: 'bytes | Data_PCAPNG | Schema_BlockType | dict[str, Any]' = b'',
             **kwargs: 'Any') -> 'Schema_PCAPNG':
        """Make PCAP-NG block data.

        Args:
            type: Block type.
            type_default: Default block type.
            type_namespace: Block type namespace.
            type_reversed: Whether to reverse block type namespace.
            block: Block data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        type_val = self._make_index(type, type_default, namespace=type_namespace,  # type: ignore[call-overload]
                                    reversed=type_reversed, pack=False)

        if isinstance(block, bytes):
            block_val = block  # type: bytes | Schema_BlockType
        elif isinstance(block, (dict, Data_PCAPNG)):
            name = self.__block__[type_val]
            if isinstance(name, str):
                meth_name = f'_make_block_{name}'
                meth = cast('BlockConstructor',
                            getattr(self, meth_name, self._make_block_unknown))
            else:
                meth = name[1]

            if isinstance(block, dict):
                block_val = meth(type_val, **block)
            else:
                block_val = meth(type_val, block)
        elif isinstance(block, Schema):
            block_val = block
        else:
            raise ProtocolError(f'PCAP-NG: [Type {type_val}] invalid format')

        return Schema_PCAPNG(
            type=type_val,
            block=block_val,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload  # type: ignore[override]
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      num: 'int', ctx: 'Context', **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, *, num: 'int', ctx: 'Context',  # pylint: disable=arguments-differ
                      **kwargs: 'Any') -> 'None': ...

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      num: 'int', ctx: 'Context', **kwargs: 'Any') -> 'None':
        """Initialisation.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            num: Frame index number.
            ctx: Section context of the PCAP-NG file.
            **kwargs: Arbitrary keyword arguments.

        Notes:
            For the first block, ``num`` will be set to ``0`` and ctx as :obj:`None`,
            such that we can be sure that the first block is the section header block.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        #: int: Block index number.
        self._fnum = num
        #: pcapkit.foundation.engins.pcapng.Context: Context of the PCAP-NG file.
        self._ctx = ctx

        if file is None:
            _read = False
            #: bytes: Raw packet data.
            self._data = self.pack(**kwargs)
            #: io.BytesIO: Source packet stream.
            self._file = io.BytesIO(self._data)
        else:
            _read = True
            #: io.BytesIO: Source packet stream.
            self._file = io.BytesIO(file) if isinstance(file, bytes) else file
        _seek_set = self._file.tell()

        #: pcapkit.corekit.infoclass.Info: Parsed packet data.
        self._info = self.unpack(length, _read=_read, _seek_set=_seek_set, **kwargs)

    def __length_hint__(self) -> 'Literal[12]':
        """Return an estimated length for the object."""
        return 12

    # NOTE: This is a hack to make the ``__index__`` method work both as a
    # class method and an instance method.
    def __index__(self: 'Optional[PCAPNG]' = None) -> 'int':  # type: ignore[override]
        """Index of the block.

        Args:
            self: :class:`PCAPNG` object or :obj:`None`.

        Returns:
            If the object is initiated, i.e. :attr:`self._fnum <pcapkit.protocols.misc.pcapng.PCAPNG._fnum>`
            exists, and is of a packet block (EPB, ISB or Packet), returns the
            block index number of itself; else raises :exc:`UnsupportedCall`.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        if self is None or self._info.type not in self.PACKET_TYPES:
            raise UnsupportedCall("'PCAPNG' object cannot be interpreted as an integer")
        return self._fnum

    ##########################################################################
    # Utilities.
    ##########################################################################
