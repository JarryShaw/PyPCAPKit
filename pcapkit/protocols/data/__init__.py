# -*- coding: utf-8 -*-
# pylint: disable=unused-wildcard-import
"""data models for protocols"""

# Base Class for Data Models
from pcapkit.protocols.data.data import *

# Base Class for Protocols
from pcapkit.protocols.data.protocol import *

# Link Layer Protocols
from pcapkit.protocols.data.link import *

# Internet Layer Protocols
from pcapkit.protocols.data.internet import *

# Transport Layer Protocols
from pcapkit.protocols.data.transport import *

# Application Layer Protocols
from pcapkit.protocols.data.application import *

# Utility Classes for Protocols
from pcapkit.protocols.data.misc import *

__all__ = [
    # Packet data
    'Packet',

    # PCAP file headers
    'PCAP_Header', 'PCAP_MagicNumber',
    'PCAP_Frame', 'PCAP_FrameInfo',

    # PCAP-NG file format
    'PCAPNG',
    'PCAPNG_Option', 'PCAPNG_UnknownOption',
    'PCAPNG_EndOfOption', 'PCAPNG_CommentOption', 'PCAPNG_CustomOption',
    'PCAPNG_IF_NameOption', 'PCAPNG_IF_DescriptionOption', 'PCAPNG_IF_IPv4AddrOption', 'PCAPNG_IF_IPv6AddrOption',
    'PCAPNG_IF_MACAddrOption', 'PCAPNG_IF_EUIAddrOption', 'PCAPNG_IF_SpeedOption', 'PCAPNG_IF_TSResolOption',
    'PCAPNG_IF_TZoneOption', 'PCAPNG_IF_FilterOption', 'PCAPNG_IF_OSOption', 'PCAPNG_IF_FCSLenOption',
    'PCAPNG_IF_TSOffsetOption', 'PCAPNG_IF_HardwareOption', 'PCAPNG_IF_TxSpeedOption', 'PCAPNG_IF_RxSpeedOption',
    'PCAPNG_EPB_FlagsOption', 'PCAPNG_EPB_HashOption', 'PCAPNG_EPB_DropCountOption', 'PCAPNG_EPB_PacketIDOption',
    'PCAPNG_EPB_QueueOption', 'PCAPNG_EPB_VerdictOption',
    'PCAPNG_NS_DNSNameOption', 'PCAPNG_NS_DNSIP4AddrOption', 'PCAPNG_NS_DNSIP6AddrOption',
    'PCAPNG_ISB_StartTimeOption', 'PCAPNG_ISB_EndTimeOption', 'PCAPNG_ISB_IFRecvOption', 'PCAPNG_ISB_IFDropOption',
    'PCAPNG_ISB_FilterAcceptOption', 'PCAPNG_ISB_OSDropOption', 'PCAPNG_ISB_UsrDelivOption',
    'PCAPNG_NameResolutionRecord', 'PCAPNG_UnknownRecord', 'PCAPNG_EndRecord', 'PCAPNG_IPv4Record', 'PCAPNG_IPv6Record',
    'PCAPNG_DSBSecrets', 'PCAPNG_UnknownSecrets', 'PCAPNG_TLSKeyLog', 'PCAPNG_WireGuardKeyLog', 'PCAPNG_ZigBeeNWKKey',
    'PCAPNG_ZigBeeAPSKey',
    'PCAPNG_UnknownBlock', 'PCAPNG_SectionHeaderBlock', 'PCAPNG_InterfaceDescriptionBlock',
    'PCAPNG_EnhancedPacketBlock', 'PCAPNG_SimplePacketBlock', 'PCAPNG_NameResolutionBlock',
    'PCAPNG_InterfaceStatisticsBlock', 'PCAPNG_SystemdJournalExportBlock', 'PCAPNG_DecryptionSecretsBlock',
    'PCAPNG_CustomBlock',

    # Address Resolution Protocol
    'ARP', 'ARP_Address', 'ARP_Type',

    # Ethernet Protocol
    'Ethernet',

    # Open Shortest Path First
    'OSPF', 'OSPF_CrytographicAuthentication',

    # 802.1Q Customer VLAN Tag Type
    'VLAN', 'VLAN_TCI',

    # Authentication Header
    'AH',

    # Host Identity Protocol
    'HIP', 'HIP_Control',
    'HIP_LocatorData', 'HIP_Locator', 'HIP_HostIdentity', 'HIP_Lifetime', 'HIP_Flags',
    'HIP_UnassignedParameter', 'HIP_ESPInfoParameter', 'HIP_R1CounterParameter',
    'HIP_LocatorSetParameter', 'HIP_PuzzleParameter', 'HIP_SolutionParameter',
    'HIP_SEQParameter', 'HIP_ACKParameter', 'HIP_DHGroupListParameter',
    'HIP_DiffieHellmanParameter', 'HIP_HIPTransformParameter', 'HIP_HIPCipherParameter',
    'HIP_NATTraversalModeParameter', 'HIP_TransactionPacingParameter', 'HIP_EncryptedParameter',
    'HIP_HostIDParameter', 'HIP_HITSuiteListParameter', 'HIP_CertParameter',
    'HIP_NotificationParameter', 'HIP_EchoRequestSignedParameter', 'HIP_RegInfoParameter',
    'HIP_RegRequestParameter', 'HIP_RegResponseParameter', 'HIP_RegFailedParameter',
    'HIP_RegFromParameter', 'HIP_EchoResponseSignedParameter', 'HIP_TransportFormatListParameter',
    'HIP_ESPTransformParameter', 'HIP_SeqDataParameter', 'HIP_AckDataParameter',
    'HIP_PayloadMICParameter', 'HIP_TransactionIDParameter', 'HIP_OverlayIDParameter',
    'HIP_RouteDstParameter', 'HIP_HIPTransportModeParameter', 'HIP_HIPMACParameter',
    'HIP_HIPMAC2Parameter', 'HIP_HIPSignature2Parameter', 'HIP_HIPSignatureParameter',
    'HIP_EchoRequestUnsignedParameter', 'HIP_EchoResponseUnsignedParameter', 'HIP_RelayFromParameter',
    'HIP_RelayToParameter', 'HIP_RouteViaParameter', 'HIP_FromParameter',
    'HIP_RVSHMACParameter', 'HIP_RelayHMACParameter',

    # Hop-by-Hop Options
    'HOPOPT',
    'HOPOPT_RPLFlags', 'HOPOPT_MPLFlags', 'HOPOPT_DFFFlags',
    'HOPOPT_UnassignedOption', 'HOPOPT_PadOption', 'HOPOPT_TunnelEncapsulationLimitOption',
    'HOPOPT_RouterAlertOption', 'HOPOPT_CALIPSOOption', 'HOPOPT_SMFIdentificationBasedDPDOption',
    'HOPOPT_SMFHashBasedDPDOption', 'HOPOPT_PDMOption', 'HOPOPT_QuickStartOption',
    'HOPOPT_RPLOption', 'HOPOPT_MPLOption', 'HOPOPT_ILNPOption',
    'HOPOPT_LineIdentificationOption', 'HOPOPT_JumboPayloadOption', 'HOPOPT_HomeAddressOption',
    'HOPOPT_IPDFFOption',

    # Internet Protocol version 4
    'IPv4',
    'IPv4_ToSField', 'IPv4_Flags',
    'IPv4_OptionType',
    'IPv4_UnassignedOption', 'IPv4_EOOLOption', 'IPv4_NOPOption',
    'IPv4_SECOption', 'IPv4_LSROption', 'IPv4_TSOption',
    'IPv4_ESECOption', 'IPv4_RROption', 'IPv4_SIDOption',
    'IPv4_SSROption', 'IPv4_MTUPOption', 'IPv4_MTUROption',
    'IPv4_TROption', 'IPv4_RTRALTOption', 'IPv4_QSOption',
    'IPv4_QuickStartRequestOption', 'IPv4_QuickStartReportOption',

    # IPv6 Fragment Header
    'IPv6_Frag',

    # IPv6 Destination Options Header
    'IPv6_Opts',
    'IPv6_Opts_RPLFlags', 'IPv6_Opts_MPLFlags', 'IPv6_Opts_DFFFlags',
    'IPv6_Opts_UnassignedOption', 'IPv6_Opts_PadOption', 'IPv6_Opts_TunnelEncapsulationLimitOption',
    'IPv6_Opts_RouterAlertOption', 'IPv6_Opts_CALIPSOOption', 'IPv6_Opts_SMFIdentificationBasedDPDOption',
    'IPv6_Opts_SMFHashBasedDPDOption', 'IPv6_Opts_PDMOption', 'IPv6_Opts_QuickStartRequestOption',
    'IPv6_Opts_QuickStartReportOption', 'IPv6_Opts_RPLOption', 'IPv6_Opts_MPLOption', 'IPv6_Opts_ILNPOption',
    'IPv6_Opts_LineIdentificationOption', 'IPv6_Opts_JumboPayloadOption', 'IPv6_Opts_HomeAddressOption',
    'IPv6_Opts_IPDFFOption',

    # IPv6 Routing Header
    'IPv6_Route',
    'IPv6_Route_UnknownType', 'IPv6_Route_SourceRoute', 'IPv6_Route_Type2', 'IPv6_Route_RPL',

    # Internet Protocol version 6
    'IPv6',

    # Internetwork Packet Exchange
    'IPX',
    'IPX_Address',

    # Mobility Header
    'MH',
    'MH_UnknownMessage', 'MH_BindingRefreshRequestMessage', 'MH_HomeTestInitMessage', 'MH_CareofTestInitMessage',
    'MH_HomeTestMessage', 'MH_CareofTestMessage', 'MH_BindingUpdateMessage', 'MH_BindingAcknowledgementMessage',
    'MH_BindingErrorMessage',
    'MH_Option',
    'MH_UnassignedOption', 'MH_PadOption', 'MH_BindingRefreshAdviceOption', 'MH_AlternateCareofAddressOption',
    'MH_NonceIndicesOption', 'MH_AuthorizationDataOption', 'MH_MobileNetworkPrefixOption',
    'MH_LinkLayerAddressOption', 'MH_MNIDOption', 'MH_AuthOption', 'MH_MesgIDOption', 'MH_CGAParametersRequestOption',
    'MH_CGAParametersOption', 'MH_SignatureOption', 'MH_PermanentHomeKeygenTokenOption', 'MH_CareofTestInitOption',
    'MH_CareofTestOption',
    'MH_CGAParameter',
    'MH_CGAExtension',
    'MH_UnknownExtension', 'MH_MultiPrefixExtension',

    # Transmission Control Protocol
    'TCP',
    'TCP_Flags', 'TCP_SACKBlock',
    'TCP_Option',
    'TCP_UnassignedOption', 'TCP_EndOfOptionList', 'TCP_NoOperation', 'TCP_MaximumSegmentSize', 'TCP_WindowScale',
    'TCP_SACKPermitted', 'TCP_SACK', 'TCP_Echo', 'TCP_EchoReply', 'TCP_Timestamps', 'TCP_PartialOrderConnectionPermitted',  # pylint: disable=line-too-long
    'TCP_PartialOrderServiceProfile', 'TCP_CC', 'TCP_CCNew', 'TCP_CCEcho', 'TCP_AlternateChecksumRequest',
    'TCP_AlternateChecksumData', 'TCP_MD5Signature', 'TCP_QuickStartResponse', 'TCP_UserTimeout',
    'TCP_Authentication', 'TCP_FastOpenCookie',
    'TCP_MPTCPCapableFlag',
    'TCP_MPTCP',
    'TCP_MPTCPUnknown', 'TCP_MPTCPCapable', 'TCP_MPTCPDSS', 'TCP_MPTCPAddAddress', 'TCP_MPTCPRemoveAddress',
    'TCP_MPTCPPriority', 'TCP_MPTCPFallback', 'TCP_MPTCPFastclose',
    'TCP_MPTCPJoin',
    'TCP_MPTCPJoinSYN', 'TCP_MPTCPJoinSYNACK', 'TCP_MPTCPJoinACK',

    # User Datagram Protocol
    'UDP',

    # File Transfer Protocol
    'FTP',
    'FTP_Request', 'FTP_Response',

    # Hypertext Transfer Protocol (HTTP/1.*)
    'HTTPv1',
    'HTTPv1_Header',
    'HTTPv1_RequestHeader', 'HTTPv1_ResponseHeader',

    # Hypertext Transfer Protocol (HTTP/2)
    'HTTPv2',
    'HTTPv2_Flags',
    'HTTPv2_DataFrameFlags', 'HTTPv2_HeadersFrameFlags', 'HTTPv2_SettingsFrameFlags',
    'HTTPv2_PushPromiseFrameFlags', 'HTTPv2_PingFrameFlags', 'HTTPv2_ContinuationFrameFlags',
    'HTTPv2_UnassignedFrame', 'HTTPv2_DataFrame', 'HTTPv2_HeadersFrame', 'HTTPv2_PriorityFrame',
    'HTTPv2_RSTStreamFrame', 'HTTPv2_SettingsFrame', 'HTTPv2_PushPromiseFrame', 'HTTPv2_PingFrame',
    'HTTPv2_GoawayFrame', 'HTTPv2_WindowUpdateFrame', 'HTTPv2_ContinuationFrame',

    # No Payload
    'NoPayload',

    # Raw Packet
    'Raw',
]
