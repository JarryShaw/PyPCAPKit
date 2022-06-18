# -*- coding: utf-8 -*-
# pylint: disable=unused-wildcard-import
"""data models for protocols"""

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
    'HIP_DeffieHellmanParameter', 'HIP_HIPTransformParameter', 'HIP_HIPCipherParameter',
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

    # IPv6 Fragment Header
    'IPv6_Frag',

    # IPv6 Destination Options Header
    'IPv6_Opts',
    'IPv6_Opts_RPLFlags', 'IPv6_Opts_MPLFlags', 'IPv6_Opts_DFFFlags',
    'IPv6_Opts_UnassignedOption', 'IPv6_Opts_PadOption', 'IPv6_Opts_TunnelEncapsulationLimitOption',
    'IPv6_Opts_RouterAlertOption', 'IPv6_Opts_CALIPSOOption', 'IPv6_Opts_SMFIdentificationBasedDPDOption',
    'IPv6_Opts_SMFHashBasedDPDOption', 'IPv6_Opts_PDMOption', 'IPv6_Opts_QuickStartOption',
    'IPv6_Opts_RPLOption', 'IPv6_Opts_MPLOption', 'IPv6_Opts_ILNPOption',
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

    # Transmission Control Protocol
    'TCP',
    'TCP_Flags',
    'TCP_Option',
    'TCP_UnassignedOption', 'TCP_EndOfOptionList', 'TCP_NoOperation', 'TCP_MaximumSegmentSize', 'TCP_WindowScale',
    'TCP_SACKPermitted', 'TCP_SACK', 'TCP_Echo', 'TCP_EchoReply', 'TCP_Timestamp', 'TCP_PartialOrderConnectionPermitted',  # pylint: disable=line-too-long
    'TCP_PartialOrderConnectionProfile', 'TCP_CC', 'TCP_CCNew', 'TCP_CCEcho', 'TCP_AlternateChecksumRequest',
    'TCP_AlternateChecksumData', 'TCP_MD5Signature', 'TCP_QuickStartResponse', 'TCP_UserTimeout',
    'TCP_Authentication', 'TCP_FastOpenCookie',
    'TCP_MPTCPCapableFlag', 'TCP_MPTCPDSSFlag',
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

    # Hypertext Transfer Protocol
    'HTTP',

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
    'HTTPv2_RstStreamFrame', 'HTTPv2_SettingsFrame', 'HTTPv2_PushPromiseFrame', 'HTTPv2_PingFrame',
    'HTTPv2_GoawayFrame', 'HTTPv2_WindowUpdateFrame', 'HTTPv2_ContinuationFrame',

    # No Payload
    'NoPayload',

    # Raw Packet
    'Raw',
]
