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
import math
import os
import platform
import re
import sys
import textwrap
import time
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.const.pcapng.filter_type import FilterType as Enum_FilterType
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
from pcapkit.protocols.data.misc.pcapng import CustomOption as Data_CustomOption
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
from pcapkit.protocols.schema.misc.pcapng import CustomOption as Schema_CustomOption
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
    from datetime import timedelta, timezone
    from decimal import Decimal
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
    from typing import IO, Any, Callable, Counter, DefaultDict, Optional, Type, Union

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

# check Python version
py38 = ((version_info := sys.version_info).major >= 3 and version_info.minor >= 8)

# Ethernet address pattern
PAT_MAC_ADDR = re.compile(rb'(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}')
# EUI address pattern
PAT_EUI_ADDR = re.compile(rb'(?i)(?:[0-9a-f]{2}[:-]){7}[0-9a-f]{2}')


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

    if TYPE_CHECKING:
        #: PCAP-NG context manager.
        _ctx: 'Optional[Context]'

        #: PCAP-NG block type.
        _type: Enum_BlockType
        #: PCAP-NG block byteorder.
        _byte: 'Literal["little", "big"]'

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
            Enum_OptionType.opt_custom_2988: 'custom',
            Enum_OptionType.opt_custom_2989: 'custom',
            Enum_OptionType.opt_custom_19372: 'custom',
            Enum_OptionType.opt_custom_19373: 'custom',
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
            Enum_SecretsType.ZigBee_NWK_Key: 'zigbee_nwk',
            Enum_SecretsType.ZigBee_APS_Key: 'zigbee_aps',
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
        if self._ctx is None:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'context'")
        return self._ctx

    @property
    def byteorder(self) -> 'Literal["big", "little"]':
        """Byteorder of the current block."""
        return self._byte

    @property
    def nanosecond(self) -> 'bool':
        """Whether the timestamp is in nanosecond."""
        if self._ctx is None or self._info.type not in self.PACKET_TYPES:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'nanosecond'")

        info = cast('Packet', self._info)
        options = self._ctx.interfaces[info.interface_id].options
        tsresol = cast('Optional[Data_IF_TSResolOption]',
                       options.get(Enum_OptionType.if_tsresol))
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
        if self._ctx is None or self._info.type not in self.PACKET_TYPES:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'linktype'")

        info = cast('Packet', self._info)
        return self._ctx.interfaces[info.interface_id].linktype

    @property
    def block(self) -> 'Enum_BlockType':
        """PCAP-NG block type."""
        return self._type

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

    @classmethod
    def register_block(cls, code: 'Enum_BlockType', meth: 'str | tuple[BlockParser, BlockConstructor]') -> 'None':
        """Register a block parser.

        Args:
            code: PCAP-NG block type code.
            meth: Method name or callable to parse and/or construct the block.

        """
        if code in cls.__block__:
            warn(f'PCAP-NG: [Type {code}] block already registered', RegistryWarning)
        cls.__block__[code] = meth

    @classmethod
    def register_option(cls, code: 'Enum_OptionType', meth: 'str | tuple[OptionParser, OptionConstructor]') -> 'None':
        """Register a option parser.

        Args:
            code: PCAP-NG option type code.
            meth: Method name or callable to parse and/or construct the option.

        """
        if code in cls.__option__:
            warn(f'PCAP-NG: [Option {code}] option already registered', RegistryWarning)
        cls.__option__[code] = meth

    @classmethod
    def register_record(cls, code: 'Enum_RecordType', meth: 'str | tuple[RecordParser, RecordConstructor]') -> 'None':
        """Register a name resolution record parser.

        Args:
            code: PCAP-NG name resolution record type code.
            meth: Method name or callable to parse and/or construct the name resolution record.

        """
        if code in cls.__record__:
            warn(f'PCAP-NG: [Type {code}] name resolution record already registered', RegistryWarning)
        cls.__record__[code] = meth

    @classmethod
    def register_secrets(cls, code: 'Enum_SecretsType', meth: 'str | tuple[SecretsParser, SecretsConstructor]') -> 'None':
        """Register a decryption secrets parser.

        Args:
            code: PCAP-NG decryption secrets type code.
            meth: Method name or callable to parse and/or construct the decryption secrets.

        """
        if code in cls.__secrets__:
            warn(f'PCAP-NG: [Secrets {code}] decryption secrets already registered', RegistryWarning)
        cls.__secrets__[code] = meth

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
            self._byte = self._ctx.section.byteorder
            packet['byteorder'] = self._byte
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
                self._byte = self._ctx.section.byteorder
                packet['byteorder'] = self._byte
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
        self._type = schema.type

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
        self._type = type_val

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
        #: collections.Counter: Counter for option types.
        self._opt = collections.Counter()  # type: Counter[Enum_OptionType]

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

    @classmethod
    def _make_data(cls, data: 'Data_PCAPNG') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'type': data.type,
            'block': data,
        }

    def _read_mac_addr(self, addr: 'bytes') -> 'str':
        """Read MAC address.

        Args:
            addr: MAC address.

        Returns:
            Colon (``:``) seperated *hex* encoded MAC address.

        """
        if py38:
            _addr = addr.hex(':')
        else:
            _addr = ':'.join(textwrap.wrap(addr.hex(), 2))
        return _addr

    def _read_eui_addr(self, addr: 'bytes') -> 'str':
        """Read EUI address.

        Args:
            addr: EUI address.

        Returns:
            Colon (``:``) seperated *hex* encoded EUI address.

        """
        if py38:
            _addr = addr.hex(':')
        else:
            _addr = ':'.join(textwrap.wrap(addr.hex(), 2))
        return _addr

    def _make_mac_addr(self, addr: 'str | bytes | bytearray') -> 'bytes':
        """Make MAC address.

        Args:
            addr: MAC address.

        Returns:
            MAC address.

        """
        _addr = addr.encode() if isinstance(addr, str) else addr

        if PAT_MAC_ADDR.fullmatch(_addr) is not None:
            return _addr.replace(b':', b'').replace(b'-', b'')
        raise ProtocolError(f'invalid MAC address: {addr!r}')

    def _make_eui_addr(self, addr: 'str | bytes | bytearray') -> 'bytes':
        """Make EUI address.

        Args:
            addr: EUI address.

        Returns:
            EUI address.

        """
        _addr = addr.encode() if isinstance(addr, str) else addr

        if PAT_EUI_ADDR.fullmatch(_addr) is not None:
            return _addr.replace(b':', b'').replace(b'-', b'')
        raise ProtocolError(f'invalid EUI address: {addr!r}')

    def _decode_next_layer(self, dict_: 'Data_PCAPNG', proto: 'Optional[int]' = None,
                           length: 'Optional[int]' = None, *, packet: 'Optional[dict[str, Any]]' = None) -> 'Data_PCAPNG':  # pylint: disable=arguments-differ
        r"""Decode next layer protocol.

        Arguments:
            dict\_: info buffer
            proto: next layer protocol index
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Current protocol with packet extracted.

        Notes:
            We added a new key ``__next_type__`` to ``dict_`` to store the
            next layer protocol type, and a new key ``__next_name__`` to
            store the next layer protocol name. These two keys will **NOT**
            be included when :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` is called.

            We also added a new key ``protocols`` to ``dict_`` to store the
            protocol chain of the current packet (frame).

        """
        next_ = cast('Protocol', self._import_next_layer(proto, length, packet=packet))  # type: ignore[misc,call-arg,redundant-cast]
        info, chain = next_.info, next_.protochain

        # make next layer protocol name
        layer = next_.info_name
        # proto = next_.__class__.__name__

        # write info and protocol chain into dict
        dict_.__update__({
            layer: info,
            'protocols': chain.chain if chain else '',
            '__next_type__': type(next_),
            '__next_name__': layer,
        })
        self._next = next_  # pylint: disable=attribute-defined-outside-init
        self._protos = chain  # pylint: disable=attribute-defined-outside-init
        return dict_

    def _read_block_unknown(self, schema: 'Schema_UnknownBlock', *,
                            header: 'Schema_PCAPNG') -> 'Data_UnknownBlock':
        """Read unknown PCAP-NG block.

        Args:
            schema: Parsed block schema.
            header: Parsed PCAP-NG header schema.

        Returns:
            Parsed packet data.

        """
        data = Data_UnknownBlock(
            type=header.type,
            length=schema.length,
            body=schema.body,
        )
        return data

    def _read_block_shb(self, schema: 'Schema_SectionHeaderBlock', *,
                        header: 'Schema_PCAPNG') -> 'Data_SectionHeaderBlock':
        """Read PCAP-NG section header block (SHB).

        Structure of Section Header Block:

        .. code-block:: text

               0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            0 |                   Block Type = 0x0A0D0D0A                     |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            4 |                      Block Total Length                       |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            8 |                      Byte-Order Magic                         |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           12 |          Major Version        |         Minor Version         |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           16 |                                                               |
              |                          Section Length                       |
              |                                                               |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           24 /                                                               /
              /                      Options (variable)                       /
              /                                                               /
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |                      Block Total Length                       |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed block schema.
            header: Parsed PCAP-NG header schema.

        Returns:
            Parsed packet data.

        """
        self._byte = schema.byteorder

        data = Data_SectionHeaderBlock(
            type=header.type,
            length=schema.length,
            byteorder=schema.byteorder,
            version=VersionInfo(
                major=schema.major,
                minor=schema.minor,
            ),
            section_length=schema.section_length,
            options=self._read_pcapng_options(schema.options),
        )
        return data



    def _read_pcapng_options(self, options_schema: 'list[Schema_Option]') -> 'Option':
        """Read PCAP-NG options.

        Structure of PCAP-NG option:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Option Code              |         Option Length         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                       Option Value                            /
           /              variable length, padded to 32 bits               /
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                                                               /
           /                 . . . other options . . .                     /
           /                                                               /
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Option Code == opt_endofopt |   Option Length == 0          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            options_schema: Parsed PCAP-NG options.

        Returns:
            Parsed PCAP-NG options data.

        """
        options = OrderedMultiDict()  # type: Option

        for schema in options_schema:
            type = schema.type
            name = self.__option__[type]

            if isinstance(name, str):
                meth_name = f'_read_option_{name}'
                meth = cast('OptionParser',
                            getattr(self, meth_name, self._read_option_unknown))
            else:
                meth = name[0]
            data = meth(schema, options=options)

            # record option data
            options.add(type, data)
            self._opt[type] += 1

            # brea when ``opt_endofopt`` is reached
            if type == Enum_OptionType.opt_endofopt:
                break

        return options

    def _read_option_unknown(self, schema: 'Schema_UnknownOption', *,
                             options: 'Option') -> 'Data_UnknownOption':
        """Read unknown PCAP-NG option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        option = Data_UnknownOption(
            type=schema.type,
            length=schema.length,
            data=schema.data,
        )
        return option

    def _read_option_endofopt(self, schema: 'Schema_EndOfOption', *,
                              options: 'Option') -> 'Data_EndOfOption':
        """Read PCAP-NG ``opt_endofopt`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [opt_endofopt] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')

        option = Data_EndOfOption(
            type=schema.type,
            length=schema.length,
        )
        return option

    def _read_option_comment(self, schema: 'Schema_CommentOption', *,
                             options: 'Option') -> 'Data_CommentOption':
        """Read PCAP-NG ``opt_comment`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        option = Data_CommentOption(
            type=schema.type,
            length=schema.length,
            comment=schema.comment,
        )
        return option

    def _read_option_custom(self, schema: 'Schema_CustomOption', *,
                            options: 'Option') -> 'Data_CustomOption':
        """Read PCAP-NG ``opt_custom`` option.

        Structure of PCAP-NG ``opt_custom`` option:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Custom Option Code        |         Option Length         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                Private Enterprise Number (PEN)                |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                        Custom Data                            /
           /              variable length, padded to 32 bits               /
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        option = Data_CustomOption(
            type=schema.type,
            length=schema.length,
            pen=schema.pen,
            data=schema.data,
        )
        return option

    def _read_option_if_name(self, schema: 'Schema_IF_NameOption', *,
                             options: 'Option') -> 'Data_IF_NameOption':
        """Read PCAP-NG ``if_name`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_name] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_name] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')

        option = Data_IF_NameOption(
            type=schema.type,
            length=schema.length,
            name=schema.name,
        )
        return option

    def _read_option_if_description(self, schema: 'Schema_IF_DescriptionOption', *,
                                    options: 'Option') -> 'Data_IF_DescriptionOption':
        """Read PCAP-NG ``if_description`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_description] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_description] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')

        option = Data_IF_DescriptionOption(
            type=schema.type,
            length=schema.length,
            description=schema.description,
        )
        return option

    def _read_option_if_ipv4(self, schema: 'Schema_IF_IPv4AddrOption', *,
                                    options: 'Option') -> 'Data_IF_IPv4AddrOption':
        """Read PCAP-NG ``if_IPv4addr`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_IPv4addr] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if schema.length != 8:
            raise ProtocolError(f'PCAP-NG [if_IPv4addr] invalid length (expected 8, got {schema.length})')

        option = Data_IF_IPv4AddrOption(
            type=schema.type,
            length=schema.length,
            interface=schema.interface,
        )
        return option

    def _read_option_if_ipv6(self, schema: 'Schema_IF_IPv6AddrOption', *,
                             options: 'Option') -> 'Data_IF_IPv6AddrOption':
        """Read PCAP-NG ``if_IPv6addr`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_IPv6addr] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if schema.length != 17:
            raise ProtocolError(f'PCAP-NG [if_IPv6addr] invalid length (expected 17, got {schema.length})')

        option = Data_IF_IPv6AddrOption(
            type=schema.type,
            length=schema.length,
            interface=schema.interface,
        )
        return option

    def _read_option_if_mac(self, schema: 'Schema_IF_MACAddrOption', *,
                            options: 'Option') -> 'Data_IF_MACAddrOption':
        """Read PCAP-NG ``if_MACaddr`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_MACaddr] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_MACaddr] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 6:
            raise ProtocolError(f'PCAP-NG [if_MACaddr] invalid length (expected 6, got {schema.length})')

        option = Data_IF_MACAddrOption(
            type=schema.type,
            length=schema.length,
            interface=self._read_mac_addr(schema.interface),
        )
        return option

    def _read_option_if_eui(self, schema: 'Schema_IF_EUIAddrOption', *,
                            options: 'Option') -> 'Data_IF_EUIAddrOption':
        """Read PCAP-NG ``if_EUIaddr`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_EUIaddr] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_EUIaddr] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 8:
            raise ProtocolError(f'PCAP-NG [if_EUIaddr] invalid length (expected 8, got {schema.length})')

        option = Data_IF_EUIAddrOption(
            type=schema.type,
            length=schema.length,
            interface=self._read_eui_addr(schema.interface),
        )
        return option

    def _read_option_if_speed(self, schema: 'Schema_IF_SpeedOption', *,
                              options: 'Option') -> 'Data_IF_SpeedOption':
        """Read PCAP-NG ``if_speed`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_speed] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_speed] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 8:
            raise ProtocolError(f'PCAP-NG [if_speed] invalid length (expected 8, got {schema.length})')

        option = Data_IF_SpeedOption(
            type=schema.type,
            length=schema.length,
            speed=schema.speed,
        )
        return option

    def _read_option_if_tsresol(self, schema: 'Schema_IF_TSResolOption', *,
                              options: 'Option') -> 'Data_IF_TSResolOption':
        """Read PCAP-NG ``if_tsresol`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_tsresol] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_tsresol] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 1:
            raise ProtocolError(f'PCAP-NG [if_tsresol] invalid length (expected 1, got {schema.length})')

        option = Data_IF_TSResolOption(
            type=schema.type,
            length=schema.length,
            resolution=schema.resolution,
        )
        return option

    def _read_option_if_tzone(self, schema: 'Schema_IF_TZoneOption', *,
                              options: 'Option') -> 'Data_IF_TZoneOption':
        """Read PCAP-NG ``if_tzone`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_tzone] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_tzone] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 4:
            raise ProtocolError(f'PCAP-NG [if_tzone] invalid length (expected 4, got {schema.length})')

        option = Data_IF_TZoneOption(
            type=schema.type,
            length=schema.length,
            timezone=datetime.timezone(datetime.timedelta(seconds=schema.tzone)),
        )
        return option

    def _read_option_if_filter(self, schema: 'Schema_IF_FilterOption', *,
                               options: 'Option') -> 'Data_IF_FilterOption':
        """Read PCAP-NG ``if_filter`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_filter] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_filter] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length < 1:
            raise ProtocolError(f'PCAP-NG [if_filter] invalid length (expected 1+, got {schema.length})')

        option = Data_IF_FilterOption(
            type=schema.type,
            length=schema.length,
            code=schema.code,
            expression=schema.filter,
        )
        return option

    def _read_option_if_os(self, schema: 'Schema_IF_OSOption', *,
                           options: 'Option') -> 'Data_IF_OSOption':
        """Read PCAP-NG ``if_os`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_os] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_os] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')

        option = Data_IF_OSOption(
            type=schema.type,
            length=schema.length,
            os=schema.os,
        )
        return option

    def _read_option_if_fcslen(self, schema: 'Schema_IF_FCSLenOption', *,
                           options: 'Option') -> 'Data_IF_FCSLenOption':
        """Read PCAP-NG ``if_fcslen`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_fcslen] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_fcslen] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 1:
            raise ProtocolError(f'PCAP-NG [if_fcslen] invalid length (expected 1, got {schema.length})')

        option = Data_IF_FCSLenOption(
            type=schema.type,
            length=schema.length,
            fcs_length=schema.fcslen,
        )
        return option

    def _read_option_if_tsoffset(self, schema: 'Schema_IF_TSOffsetOption', *,
                               options: 'Option') -> 'Data_IF_TSOffsetOption':
        """Read PCAP-NG ``if_tsoffset`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_tsoffset] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_tsoffset] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 8:
            raise ProtocolError(f'PCAP-NG [if_tsoffset] invalid length (expected 8, got {schema.length})')

        option = Data_IF_TSOffsetOption(
            type=schema.type,
            length=schema.length,
            offset=schema.tsoffset,
        )
        return option

    def _read_option_if_hardware(self, schema: 'Schema_IF_HardwareOption', *,
                                 options: 'Option') -> 'Data_IF_HardwareOption':
        """Read PCAP-NG ``if_hardware`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_hardware] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_hardware] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')

        option = Data_IF_HardwareOption(
            type=schema.type,
            length=schema.length,
            hardware=schema.hardware,
        )
        return option

    def _read_option_if_txspeed(self, schema: 'Schema_IF_TxSpeedOption', *,
                                options: 'Option') -> 'Data_IF_TxSpeedOption':
        """Read PCAP-NG ``if_txspeed`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_txspeed] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_txspeed] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 8:
            raise ProtocolError(f'PCAP-NG [if_txspeed] invalid length (expected 8, got {schema.length})')

        option = Data_IF_TxSpeedOption(
            type=schema.type,
            length=schema.length,
            speed=schema.tx_speed,
        )
        return option

    def _read_option_if_rxspeed(self, schema: 'Schema_IF_RxSpeedOption', *,
                                options: 'Option') -> 'Data_IF_RxSpeedOption':
        """Read PCAP-NG ``if_rxspeed`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_rxspeed] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_rxspeed] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 8:
            raise ProtocolError(f'PCAP-NG [if_rxspeed] invalid length (expected 8, got {schema.length})')

        option = Data_IF_RxSpeedOption(
            type=schema.type,
            length=schema.length,
            speed=schema.rx_speed,
        )
        return option

    def _read_option_epb_flags(self, schema: 'Schema_EPB_FlagsOption', *,
                               options: 'Option') -> 'Data_EPB_FlagsOption':
        """Read PCAP-NG ``epb_flags`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Enhanced_Packet_Block:
            raise ProtocolError(f'PCAP-NG: [epb_flags] option must be in Enhanced Packet Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [epb_flags] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 4:
            raise ProtocolError(f'PCAP-NG [epb_dropcount] invalid length (expected 8, got {schema.length})')

        option = Data_EPB_FlagsOption(
            type=schema.type,
            length=schema.length,
            direction=PacketDirection(schema.flags['direction']),
            reception=PacketReception(schema.flags['reception']),
            fcs_len=schema.flags['fcs_len'],
            crc_error=bool(schema.flags['crc_error']),
            too_long=bool(schema.flags['too_long']),
            too_short=bool(schema.flags['too_short']),
            gap_error=bool(schema.flags['gap_error']),
            unaligned_error=bool(schema.flags['unaligned_error']),
            delimiter_error=bool(schema.flags['delimiter_error']),
            preamble_error=bool(schema.flags['preamble_error']),
            symbol_error=bool(schema.flags['symbol_error']),
        )
        return option

    def _read_option_epb_hash(self, schema: 'Schema_EPB_HashOption', *,
                              options: 'Option') -> 'Data_EPB_HashOption':
        """Read PCAP-NG ``epb_hash`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Enhanced_Packet_Block:
            raise ProtocolError(f'PCAP-NG: [epb_hash] option must be in Enhanced Packet Block, '
                                f'but found in {self._type} block.')

        option = Data_EPB_HashOption(
            type=schema.type,
            length=schema.length,
            algorithm=schema.func,
            hash=schema.data,
        )
        return option

    def _read_option_epb_dropcount(self, schema: 'Schema_EPB_DropCountOption', *,
                                   options: 'Option') -> 'Data_EPB_DropCountOption':
        """Read PCAP-NG ``epb_dropcount`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Enhanced_Packet_Block:
            raise ProtocolError(f'PCAP-NG: [epb_dropcount] option must be in Enhanced Packet Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [epb_dropcount] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 8:
            raise ProtocolError(f'PCAP-NG [epb_dropcount] invalid length (expected 8, got {schema.length})')

        option = Data_EPB_DropCountOption(
            type=schema.type,
            length=schema.length,
            drop_count=schema.drop_count,
        )
        return option

    def _read_option_epb_packetid(self, schema: 'Schema_EPB_PacketIDOption', *,
                                  options: 'Option') -> 'Data_EPB_PacketIDOption':
        """Read PCAP-NG ``epb_packetid`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Enhanced_Packet_Block:
            raise ProtocolError(f'PCAP-NG: [epb_packetid] option must be in Enhanced Packet Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [epb_packetid] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 8:
            raise ProtocolError(f'PCAP-NG [epb_packetid] invalid length (expected 8, got {schema.length})')

        option = Data_EPB_PacketIDOption(
            type=schema.type,
            length=schema.length,
            packet_id=schema.packet_id,
        )
        return option

    def _read_option_epb_queue(self, schema: 'Schema_EPB_QueueOption', *,
                               options: 'Option') -> 'Data_EPB_QueueOption':
        """Read PCAP-NG ``epb_queue`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Enhanced_Packet_Block:
            raise ProtocolError(f'PCAP-NG: [epb_queue] option must be in Enhanced Packet Block, '
                                f'but found in {self._type} block.')
        if self._opt[schema.type] > 0:
            raise ProtocolError(f'PCAP-NG: [epb_queue] option must be only one, '
                                f'but {self._opt[schema.type] + 1} found.')
        if schema.length != 4:
            raise ProtocolError(f'PCAP-NG [epb_packetid] invalid length (expected 4, got {schema.length})')

        option = Data_EPB_QueueOption(
            type=schema.type,
            length=schema.length,
            queue_id=schema.queue_id,
        )
        return option

    def _read_option_epb_verdict(self, schema: 'Schema_EPB_VerdictOption', *,
                                 options: 'Option') -> 'Data_EPB_VerdictOption':
        """Read PCAP-NG ``epb_verdict`` option.

        Args:
            schema: Parsed option schema.
            options: Parsed PCAP-NG options.

        Returns:
            Constructed option data.

        """
        if self._type != Enum_BlockType.Enhanced_Packet_Block:
            raise ProtocolError(f'PCAP-NG: [epb_verdict] option must be in Enhanced Packet Block, '
                                f'but found in {self._type} block.')
        if schema.length < 1:
            raise ProtocolError(f'PCAP-NG [epb_verdict] invalid length (expected 1+, got {schema.length})')

        option = Data_EPB_VerdictOption(
            type=schema.type,
            length=schema.length,
            verdict=schema.verdict,
            value=schema.value,
        )
        return option



    def _make_block_unknown(self, block: 'Optional[Data_UnknownBlock]' = None, *,
                            data: 'bytes' = b'',
                            **kwargs: 'Any') -> 'Schema_UnknownBlock':
        """Make unknown PCAP-NG block.

        Args:
            block: Block data model.
            data: Unspecified block data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed block schema.

        """
        if block is not None:
            data = block.body

        length = len(data)

        return Schema_UnknownBlock(
            length=length,
            body=data,
            length2=length,
        )

    def _make_block_shb(self, block: 'Optional[Data_SectionHeaderBlock]' = None, *,
                        version: 'tuple[int, int] | VersionInfo' = (1, 0),
                        major_version: 'Optional[int]' = None,
                        minor_version: 'Optional[int]' = None,
                        section_length: 'int' = -1,
                        options: 'Optional[Option | list[Schema_Option | tuple[Enum_OptionType, dict[str, Any]] | bytes]]' = None,
                        **kwargs: 'Any') -> 'Schema_SectionHeaderBlock':
        """Make PCAP-NG section header block (SHB).

        Args:
            block: Block data model.
            version: Version information.
            major_version: Major version number.
            minor_version: Minor version number.
            section_length: Section length.
            options: Block options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed block schema.

        """
        self._byte = sys.byteorder

        if block is not None:
            major_version = cast('int', block.version.major)
            minor_version = cast('int', block.version.minor)
            section_length = block.section_length
            options = block.options
        else:
            if major_version is None:
                major_version = cast('int', version[0])
            if minor_version is None:
                minor_version = cast('int', version[1])

        if options is not None:
            options_value, total_length = self._make_pcapng_options(options)
        else:
            options_value, total_length = [], 0

        return Schema_SectionHeaderBlock(
            length=total_length + 28,
            magic=0x1A2B3C4D,
            major=major_version,
            minor=minor_version,
            section_length=section_length,
            options=options_value,
            length2=total_length + 28,
        )



    def _make_pcapng_options(self, options: 'Option | list[Schema_Option | tuple[Enum_OptionType, dict[str, Any]] | bytes]') -> 'tuple[list[Schema_Option | bytes], int]':
        """Make options for PCAP-NG.

        Args:
            options: PCAP-NG options.

        Returns:
            Tuple of options and total length of options.

        """
        has_endofopt = False
        total_length = 0
        if isinstance(options, list):
            options_list = []  # type: list[Schema_Option | bytes]
            for schema in options:
                if isinstance(schema, bytes):
                    code = Enum_OptionType.get(int.from_bytes(schema[0:2], self._byte, signed=False))
                    if code == Enum_OptionType.opt_endofopt:  # ignore opt_endofopt by default
                        has_endofopt = True
                        continue

                    data = schema  # type: Schema_Option | bytes
                    data_len = len(data)
                elif isinstance(schema, Schema):
                    code = schema.type
                    if code == Enum_OptionType.opt_endofopt:  # ignore opt_endofopt by default
                        has_endofopt = True
                        continue

                    data = schema
                    data_len = len(schema.pack())
                else:
                    code, args = cast('tuple[Enum_OptionType, dict[str, Any]]', schema)
                    if code == Enum_OptionType.opt_endofopt:  # ignore opt_endofopt by default
                        has_endofopt = True
                        continue

                    name = self.__option__[code]
                    if isinstance(name, str):
                        meth_name = f'_make_option_{name}'
                        meth = cast('OptionConstructor',
                                    getattr(self, meth_name, self._make_option_unknown))
                    else:
                        meth = name[1]

                    data = meth(code, **args)
                    data_len = len(data.pack())

                options_list.append(data)
                total_length += data_len
                self._opt[code] += 1

            if has_endofopt:
                opt_endofopt = self._make_option_endofopt(Enum_OptionType.opt_endofopt)
                total_length += len(opt_endofopt.pack())
                options_list.append(opt_endofopt)
            return options_list, total_length

        options_list = []
        for code, option in options.items(multi=True):
            if code == Enum_OptionType.opt_endofopt:  # ignore opt_endofopt by default
                has_endofopt = True
                continue

            name = self.__option__[code]
            if isinstance(name, str):
                meth_name = f'_make_option_{name}'
                meth = cast('OptionConstructor',
                            getattr(self, meth_name, self._make_option_unknown))
            else:
                meth = name[1]

            data = meth(code, option)
            data_len = len(data.pack())

            options_list.append(data)
            total_length += data_len
            self._opt[code] += 1

        if has_endofopt:
            opt_endofopt = self._make_option_endofopt(Enum_OptionType.opt_endofopt)
            total_length += len(opt_endofopt.pack())
            options_list.append(opt_endofopt)
        return options_list, total_length

    def _make_option_unknown(self, type: 'Enum_OptionType', option: 'Optional[Data_UnknownOption]' = None, *,
                             data: 'bytes' = b'',
                             **kwargs: 'Any') -> 'Schema_UnknownOption':
        """Make unknown PCAP-NG option.

        Args:
            type: Option type.
            option: Option data model.
            data: Unspecified option data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            data = option.data

        length = len(data)

        return Schema_UnknownOption(
            type=type,
            length=length,
            data=data,
        )

    def _make_option_endofopt(self, type: 'Enum_OptionType', option: 'Optional[Data_EndOfOption]' = None,
                              **kwargs: 'Any') -> 'Schema_EndOfOption':
        """Make PCAP-NG ``opt_endofopt`` option.

        Args:
            type: Option type.
            option: Option data model.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [opt_endofopt] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        return Schema_EndOfOption(
            type=type,
            length=0,
        )

    def _make_option_comment(self, type: 'Enum_OptionType', option: 'Optional[Data_CommentOption]' = None, *,
                             comment: 'str' = '',
                             **kwargs: 'Any') -> 'Schema_CommentOption':
        """Make PCAP-NG ``opt_comment`` option.

        Args:
            type: Option type.
            option: Option data model.
            comment: Comment text.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            comment = option.comment

        return Schema_CommentOption(
            type=type,
            length=len(comment),
            comment=comment,
        )

    def _make_option_custom(self, type: 'Enum_OptionType', option: 'Optional[Data_CustomOption]' = None, *,
                            pen: 'int' = 0xFFFFFFFF,
                            data: 'bytes' = b'',
                            **kwargs: 'Any') -> 'Schema_CustomOption':
        """Make PCAP-NG ``opt_custom`` option.

        Args:
            type: Option type.
            option: Option data model.
            pen: Private enterprise number.
            data: Custom data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            pen = option.pen
            data = option.data

        return Schema_CustomOption(
            type=type,
            length=len(data) + 4,
            pen=pen,
            data=data
        )

    def _make_option_if_name(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_NameOption]' = None, *,
                             name: 'str' = '',
                             **kwargs: 'Any') -> 'Schema_IF_NameOption':
        """Make PCAP-NG ``if_name`` option.

        Args:
            type: Option type.
            option: Option data model.
            name: Interface name.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_name] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_name] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            name = option.name

        return Schema_IF_NameOption(
            type=type,
            length=len(name),
            name=name,
        )

    def _make_option_if_description(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_DescriptionOption]' = None, *,
                                    description: 'str' = '',
                                    **kwargs: 'Any') -> 'Schema_IF_DescriptionOption':
        """Make PCAP-NG ``if_description`` option.

        Args:
            type: Option type.
            option: Option data model.
            description: Interface description.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_description] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_description] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            description = option.description

        return Schema_IF_DescriptionOption(
            type=type,
            length=len(description),
            description=description,
        )

    def _make_option_if_ipv4(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_IPv4AddrOption]' = None, *,
                             interface: 'IPv4Interface | str' = '192.168.1.1/255.255.255.0',
                             **kwargs: 'Any') -> 'Schema_IF_IPv4AddrOption':
        """Make PCAP-NG ``if_IPv4addr`` option.

        Args:
            type: Option type.
            option: Option data model.
            interface: IPv4 interface.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_IPv4addr] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')

        if option is not None:
            interface = option.interface

        return Schema_IF_IPv4AddrOption(
            type=type,
            length=8,
            interface=interface,
        )

    def _make_option_if_ipv6(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_IPv6AddrOption]' = None, *,
                             interface: 'IPv6Interface | str' = '2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64',
                             **kwargs: 'Any') -> 'Schema_IF_IPv6AddrOption':
        """Make PCAP-NG ``if_IPv6addr`` option.

        Args:
            type: Option type.
            option: Option data model.
            interface: IPv6 interface.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_IPv6addr] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')

        if option is not None:
            interface = option.interface

        return Schema_IF_IPv6AddrOption(
            type=type,
            length=8,
            interface=interface,
        )

    def _make_option_if_mac(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_MACAddrOption]' = None, *,
                            interface: 'str | bytes | bytearray' = '00:01:02:03:04:05',
                            **kwargs: 'Any') -> 'Schema_IF_MACAddrOption':
        """Make PCAP-NG ``if_MACaddr`` option.

        Args:
            type: Option type.
            option: Option data model.
            interface: MAC interface address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_MACaddr] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_MACaddr] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            interface = option.interface

        return Schema_IF_MACAddrOption(
            type=type,
            length=6,
            interface=self._make_mac_addr(interface),
        )

    def _make_option_if_eui(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_EUIAddrOption]' = None, *,
                            interface: 'str | bytes | bytearray' = '02:34:56:FF:FE:78:9A:BC',
                            **kwargs: 'Any') -> 'Schema_IF_EUIAddrOption':
        """Make PCAP-NG ``if_EUIaddr`` option.

        Args:
            type: Option type.
            option: Option data model.
            interface: Hardware EUI address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_EUIaddr] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_EUIaddr] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            interface = option.interface

        return Schema_IF_EUIAddrOption(
            type=type,
            length=8,
            interface=self._make_eui_addr(interface),
        )

    def _make_option_if_speed(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_SpeedOption]' = None, *,
                              speed: 'int' = 100000000,
                              **kwargs: 'Any') -> 'Schema_IF_SpeedOption':
        """Make PCAP-NG ``if_speed`` option.

        Args:
            type: Option type.
            option: Option data model.
            speed: Interface speed, in bits per second.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_speed] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_speed] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            speed = option.speed

        return Schema_IF_SpeedOption(
            type=type,
            length=8,
            speed=speed,
        )

    def _make_option_if_tsresol(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_TSResolOption]' = None, *,
                                resolution: 'int' = 1000000,
                                **kwargs: 'Any') -> 'Schema_IF_TSResolOption':
        """Make PCAP-NG ``if_tsresol`` option.

        Args:
            type: Option type.
            option: Option data model.
            resolution: Resolution of timestamps, in units per second.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_tsresol] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_tsresol] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            resolution = option.resolution

        test = math.log10(resolution).as_integer_ratio()[1]
        if test == 1:
            flag = 0
            resl = int(math.log10(resolution))
        else:
            test = math.log2(resolution).as_integer_ratio()[1]
            if test == 1:
                flag = 1
                resl = int(math.log2(resolution))
            else:
                raise ProtocolError(f'PCAP-NG: [if_tsresol] option resolution must be power of 10 or 2, '
                                    f'but {resolution} found.')

        return Schema_IF_TSResolOption(
            type=type,
            length=1,
            tsresol={
                'flag': flag,
                'resolution': resl,
            },
        )

    def _make_option_if_tzone(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_TZoneOption]' = None, *,
                              tzone: 'timezone | timedelta | int' = 0,
                              **kwargs: 'Any') -> 'Schema_IF_TZoneOption':
        """Make PCAP-NG ``if_tzone`` option.

        Args:
            type: Option type.
            option: Option data model.
            tzone: Timezone offset, in seconds.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_tzone] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_tzone] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            tzone = option.timezone

        if isinstance(tzone, int):
            tzone_val = tzone
        elif isinstance(tzone, datetime.timedelta):
            tzone_val = int(tzone.total_seconds())
        elif isinstance(tzone, datetime.timezone):
            tzone_val = int(tzone.utcoffset(None).total_seconds())
        else:
            raise ProtocolError(f'PCAP-NG: [if_tzone] option timezone must be int, timedelta or timezone, '
                                f'but {type(tzone).__name__} found.')

        return Schema_IF_TZoneOption(
            type=type,
            length=4,
            tzone=tzone_val,
        )

    def _make_option_if_filter(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_FilterOption]' = None, *,
                               filter: 'Enum_FilterType  | StdlibEnum | AenumEnum | str | int' = Enum_FilterType(0),
                               filter_default: 'Optional[int]' = None,
                               filter_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                               filter_reversed: 'bool' = False,
                               expression: 'bytes | str' = b'',
                               **kwargs: 'Any') -> 'Schema_IF_FilterOption':
        """Make PCAP-NG ``if_filter`` option.

        Args:
            type: Option type.
            option: Option data model.
            filter: Filter type.
            filter_default: Default filter value.
            filter_namespace: Filter namespace.
            filter_reversed: Whether filter namespace is reversed.
            expression: Filter expression.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_filter] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_filter] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            filter_val = option.code
            expr_val = option.expression
        else:
            filter_val = self._make_index(filter, filter_default, namespace=filter_namespace,  # type: ignore[call-overload]
                                          reversed=filter_reversed, pack=False)
            expr_val = expression if isinstance(expression, bytes) else expression.encode()

        return Schema_IF_FilterOption(
            type=type,
            length=1 + len(expr_val),
            code=filter_val,
            filter=expr_val,
        )

    def _make_option_if_os(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_OSOption]' = None, *,
                           os: 'str' = platform.platform(),
                           **kwargs: 'Any') -> 'Schema_IF_OSOption':
        """Make PCAP-NG ``if_os`` option.

        Args:
            type: Option type.
            option: Option data model.
            os: Operating system name.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_os] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_os] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            os = option.os

        return Schema_IF_OSOption(
            type=type,
            length=len(os),
            os=os,
        )

    def _make_option_if_fcslen(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_FCSLenOption]' = None, *,
                               fcs_length: 'int' = 4,
                               **kwargs: 'Any') -> 'Schema_IF_FCSLenOption':
        """Make PCAP-NG ``if_fcslen`` option.

        Args:
            type: Option type.
            option: Option data model.
            fcs_length: FCS length, in bytes.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_fcslen] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_fcslen] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            fcs_length = option.fcs_length

        return Schema_IF_FCSLenOption(
            type=type,
            length=1,
            fcslen=fcs_length,
        )

    def _make_option_if_hardware(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_HardwareOption]' = None, *,
                                 hardware: 'str' = platform.processor(),
                                 **kwargs: 'Any') -> 'Schema_IF_HardwareOption':
        """Make PCAP-NG ``if_hardware`` option.

        Args:
            type: Option type.
            option: Option data model.
            os: Operating system name.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_hardware] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_hardware] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            hardware = option.hardware

        return Schema_IF_HardwareOption(
            type=type,
            length=len(hardware),
            hardware=hardware,
        )

    def _make_option_if_txspeed(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_TxSpeedOption]' = None, *,
                                speed: 'int' = 100000000,
                                **kwargs: 'Any') -> 'Schema_IF_TxSpeedOption':
        """Make PCAP-NG ``if_txspeed`` option.

        Args:
            type: Option type.
            option: Option data model.
            speed: Interface transmit speed, in bits per second.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_txspeed] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_txspeed] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            speed = option.speed

        return Schema_IF_TxSpeedOption(
            type=type,
            length=8,
            tx_speed=speed,
        )

    def _make_option_if_rxspeed(self, type: 'Enum_OptionType', option: 'Optional[Data_IF_RxSpeedOption]' = None, *,
                                speed: 'int' = 100000000,
                                **kwargs: 'Any') -> 'Schema_IF_RxSpeedOption':
        """Make PCAP-NG ``if_rxspeed`` option.

        Args:
            type: Option type.
            option: Option data model.
            speed: Interface receive speed, in bits per second.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Interface_Description_Block:
            raise ProtocolError(f'PCAP-NG: [if_txspeed] option must be in Interface Description Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [if_txspeed] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            speed = option.speed

        return Schema_IF_RxSpeedOption(
            type=type,
            length=8,
            rx_speed=speed,
        )

    def _make_option_epb_flags(self, type: 'Enum_OptionType', option: 'Optional[Data_EPB_FlagsOption]' = None, *,
                               direction: 'PacketDirection | StdlibEnum | AenumEnum | str | int' = PacketDirection.UNKNOWN,
                               direction_default: 'Optional[int]' = None,
                               direction_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                               direction_reversed: 'bool' = False,
                               reception: 'PacketReception | StdlibEnum | AenumEnum | str | int' = PacketReception.UNKNOWN,
                               reception_default: 'Optional[int]' = None,
                               reception_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                               reception_reversed: 'bool' = False,
                               fcs_len: 'int' = 0,
                               crc_error: 'bool' = False,
                               too_long: 'bool' = False,
                               too_short: 'bool' = False,
                               gap_error: 'bool' = False,
                               unaligned_error: 'bool' = False,
                               delimiter_error: 'bool' = False,
                               preamble_error: 'bool' = False,
                               symbol_error: 'bool' = False,
                               **kwargs: 'Any') -> 'Schema_EPB_FlagsOption':
        """Make PCAP-NG ``epb_flags`` option.

        Args:
            type: Option type.
            option: Option data model.
            direction: Packet direction.
            direction_default: Default value of packet direction.
            direction_namespace: Namespace of packet direction.
            direction_reversed: Whether to reverse packet direction namespace.
            reception: Packet reception.
            reception_default: Default value of packet reception.
            reception_namespace: Namespace of packet reception.
            reception_reversed: Whether to reverse packet reception namespace.
            fcs_len: Length of FCS field, in bytes.
            crc_error: Whether CRC error occurred.
            too_long: Whether packet is too long.
            too_short: Whether packet is too short.
            gap_error: Whether gap error occurred.
            unaligned_error: Whether unaligned error occurred.
            delimiter_error: Whether delimiter error occurred.
            preamble_error: Whether preamble error occurred.
            symbol_error: Whether symbol error occurred.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Enhanced_Packet_Block:
            raise ProtocolError(f'PCAP-NG: [epb_flags] option must be in Enhanced Packet Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [epb_flags] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            direction_val = option.direction
            reception_val = option.reception
            fcs_len = option.fcs_len
            crc_error = option.crc_error
            too_long = option.too_long
            too_short = option.too_short
            gap_error = option.gap_error
            unaligned_error = option.unaligned_error
            delimiter_error = option.delimiter_error
            preamble_error = option.preamble_error
            symbol_error = option.symbol_error
        else:
            direction_val = self._make_index(direction, direction_default, namespace=direction_namespace,  # type: ignore[call-overload]
                                             reversed=direction_reversed, unpack=False)
            reception_val = self._make_index(reception, reception_default, namespace=reception_namespace,  # type: ignore[call-overload]
                                             reversed=reception_reversed, unpack=False)

        return Schema_EPB_FlagsOption(
            type=type,
            length=4,
            flags={
                'direction': direction_val.value,
                'reception': reception_val.value,
                'fcs_len': fcs_len,
                'crc_error': int(crc_error),
                'too_long': int(too_long),
                'too_short': int(too_short),
                'gap_error': int(gap_error),
                'unaligned_error': int(unaligned_error),
                'delimiter_error': int(delimiter_error),
                'preamble_error': int(preamble_error),
                'symbol_error': int(symbol_error),
            },
        )

    def _make_option_epb_hash(self, type: 'Enum_OptionType', option: 'Optional[Data_EPB_HashOption]' = None, *,
                              algorithm: 'Enum_HashAlgorithm | StdlibEnum | AenumEnum | int | str' = Enum_HashAlgorithm.two_s_complement,
                              algorithm_default: 'Optional[int]' = None,
                              algorithm_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                              algorithm_reversed: 'bool' = False,
                              hash: 'bytes' = b'',
                              **kwargs: 'Any') -> 'Schema_EPB_HashOption':
        """Make PCAP-NG ``epb_hash`` option.

        Args:
            type: Option type.
            option: Option data model.
            algorithm: Hash algorithm.
            algorithm_default: Default value of hash algorithm.
            algorithm_namespace: Namespace of hash algorithm.
            algorithm_reversed: Whether to reverse hash algorithm namespace.
            hash: Hash value.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Enhanced_Packet_Block:
            raise ProtocolError(f'PCAP-NG: [epb_hash] option must be in Enhanced Packet Block, '
                                f'but found in {self._type} block.')

        if option is not None:
            algo_val = option.algorithm
            hash = option.hash
        else:
            algo_val = self._make_index(algorithm, algorithm_default, namespace=algorithm_namespace,  # type: ignore[call-overload]
                                        reversed=algorithm_reversed, unpack=False)

        return Schema_EPB_HashOption(
            type=type,
            length=1 + len(hash),
            func=algo_val,
            data=hash,
        )

    def _make_option_epb_dropcount(self, type: 'Enum_OptionType', option: 'Optional[Data_EPB_DropCountOption]' = None, *,
                                   drop_count: 'int' = 0,
                                   **kwargs: 'Any') -> 'Schema_EPB_DropCountOption':
        """Make PCAP-NG ``epb_dropcount`` option.

        Args:
            type: Option type.
            option: Option data model.
            drop_count: Number of dropped packets.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Enhanced_Packet_Block:
            raise ProtocolError(f'PCAP-NG: [epb_dropcount] option must be in Enhanced Packet Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [epb_dropcount] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            drop_count = option.drop_count

        return Schema_EPB_DropCountOption(
            type=type,
            length=8,
            drop_count=drop_count,
        )

    def _make_option_epb_packetid(self, type: 'Enum_OptionType', option: 'Optional[Data_EPB_PacketIDOption]' = None, *,
                                  packet_id: 'int' = 0,
                                  **kwargs: 'Any') -> 'Schema_EPB_PacketIDOption':
        """Make PCAP-NG ``epb_packetid`` option.

        Args:
            type: Option type.
            option: Option data model.
            packet_id: Packet ID.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Enhanced_Packet_Block:
            raise ProtocolError(f'PCAP-NG: [epb_packetid] option must be in Enhanced Packet Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [epb_packetid] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            packet_id = option.packet_id

        return Schema_EPB_PacketIDOption(
            type=type,
            length=8,
            packet_id=packet_id,
        )

    def _make_option_epb_queue(self, type: 'Enum_OptionType', option: 'Optional[Data_EPB_QueueOption]' = None, *,
                               queue_id: 'int' = 0,
                               **kwargs: 'Any') -> 'Schema_EPB_QueueOption':
        """Make PCAP-NG ``epb_queue`` option.

        Args:
            type: Option type.
            option: Option data model.
            queue_id: Queue ID.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Enhanced_Packet_Block:
            raise ProtocolError(f'PCAP-NG: [epb_queue] option must be in Enhanced Packet Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [epb_queue] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            queue_id = option.queue_id

        return Schema_EPB_QueueOption(
            type=type,
            length=4,
            queue_id=queue_id,
        )

    def _make_option_epb_verdict(self, type: 'Enum_OptionType', option: 'Optional[Data_EPB_VerdictOption]' = None, *,
                                 verdict: 'Enum_VerdictType  | StdlibEnum | AenumEnum | str | int' = Enum_VerdictType.Hardware,
                                 verdict_default: 'Optional[int]' = None,
                                 verdict_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                 verdict_reversed: 'bool' = False,
                                 value: 'bytes' = b'',
                                 **kwargs: 'Any') -> 'Schema_EPB_VerdictOption':
        """Make PCAP-NG ``epb_verdict`` option.

        Args:
            type: Option type.
            option: Option data model.
            verdict: Verdict type.
            verdict_default: Default value for verdict.
            verdict_namespace: Namespace for verdict.
            verdict_reversed: Whether to reverse the namespace.
            value: Verdict value.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if self._type != Enum_BlockType.Enhanced_Packet_Block:
            raise ProtocolError(f'PCAP-NG: [epb_verdict] option must be in Enhanced Packet Block, '
                                f'but found in {self._type} block.')
        if self._opt[type] > 0:
            raise ProtocolError(f'PCAP-NG: [epb_verdict] option must be only one, '
                                f'but {self._opt[type] + 1} found.')

        if option is not None:
            verdict_val = option.verdict
            value = option.value
        else:
            verdict_val = self._make_index(verdict, verdict_default, namespace=verdict_namespace,  # type: ignore[call-overload]
                                          reversed=verdict_reversed, pack=False)

        return Schema_EPB_VerdictOption(
            type=type,
            length=1 + len(value),
            verdict=verdict_val,
            value=value,
        )
