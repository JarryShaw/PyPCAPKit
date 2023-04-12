# -*- coding: utf-8 -*-
# pylint: disable=unused-wildcard-import
"""header schema for protocols"""

# Base Class for Header Schema
from pcapkit.protocols.schema.schema import *

# Link Layer Protocols
from pcapkit.protocols.schema.link import *

# Internet Layer Protocols
from pcapkit.protocols.schema.internet import *

# Transport Layer Protocols
from pcapkit.protocols.schema.transport import *

# Application Layer Protocols
from pcapkit.protocols.schema.application import *

# Utility Classes for Protocols
from pcapkit.protocols.schema.misc import *

__all__ = [
    # Link Layer Protocols
    'ARP',
    'Ethernet',
    'L2TP',
    'OSPF', 'OSPF_CrytographicAuthentication',
    'VLAN', 'VLAN_TCI',

    # Internet Layer Protocols
    'AH',
    'HIP',
    'HIP_LocatorData', 'HIP_Locator', 'HIP_ECDSACurveHostIdentity', 'HIP_ECDSALowCurveHostIdentity',
    'HIP_EdDSACurveHostIdentity', 'HIP_HostIdentity',
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
    'IPv4',
    'IPv4_OptionType',
    'IPv4_UnassignedOption', 'IPv4_EOOLOption', 'IPv4_NOPOption',
    'IPv4_SECOption', 'IPv4_LSROption', 'IPv4_TSOption',
    'IPv4_ESECOption', 'IPv4_RROption', 'IPv4_SIDOption',
    'IPv4_SSROption', 'IPv4_MTUPOption', 'IPv4_MTUROption',
    'IPv4_TROption', 'IPv4_RTRALTOption', 'IPv4_QSOption',
    'IPv4_QuickStartRequestOption', 'IPv4_QuickStartReportOption',
    'IPv6_Frag',
    'IPv6_Opts',
    'IPv6_Opts_UnassignedOption', 'IPv6_Opts_PadOption', 'IPv6_Opts_TunnelEncapsulationLimitOption',
    'IPv6_Opts_RouterAlertOption', 'IPv6_Opts_CALIPSOOption', 'IPv6_Opts_SMFIdentificationBasedDPDOption',
    'IPv6_Opts_SMFHashBasedDPDOption', 'IPv6_Opts_PDMOption', 'IPv6_Opts_QuickStartRequestOption',
    'IPv6_Opts_QuickStartReportOption', 'IPv6_Opts_RPLOption', 'IPv6_Opts_MPLOption', 'IPv6_Opts_ILNPOption',
    'IPv6_Opts_LineIdentificationOption', 'IPv6_Opts_JumboPayloadOption', 'IPv6_Opts_HomeAddressOption',
    'IPv6_Opts_IPDFFOption',
    'IPv6_Route',
    'IPv6_Route_UnknownType', 'IPv6_Route_SourceRoute', 'IPv6_Route_Type2', 'IPv6_Route_RPL',
    'IPv6',
    'IPX',

    # Transport Layer Protocols
    'TCP',
    'TCP_SACKBlock',
    'TCP_Option',
    'TCP_UnassignedOption', 'TCP_EndOfOptionList', 'TCP_NoOperation', 'TCP_MaximumSegmentSize', 'TCP_WindowScale',
    'TCP_SACKPermitted', 'TCP_SACK', 'TCP_Echo', 'TCP_EchoReply', 'TCP_Timestamp', 'TCP_PartialOrderConnectionPermitted',  # pylint: disable=line-too-long
    'TCP_PartialOrderConnectionProfile', 'TCP_CC', 'TCP_CCNew', 'TCP_CCEcho', 'TCP_AlternateChecksumRequest',
    'TCP_AlternateChecksumData', 'TCP_MD5Signature', 'TCP_QuickStartResponse', 'TCP_UserTimeout',
    'TCP_Authentication', 'TCP_FastOpenCookie',
    'TCP_MPTCP',
    'TCP_MPTCPUnknown', 'TCP_MPTCPCapable', 'TCP_MPTCPDSS', 'TCP_MPTCPAddAddress', 'TCP_MPTCPRemoveAddress',
    'TCP_MPTCPPriority', 'TCP_MPTCPFallback', 'TCP_MPTCPFastclose',
    'TCP_MPTCPJoin',
    'TCP_MPTCPJoinSYN', 'TCP_MPTCPJoinSYNACK', 'TCP_MPTCPJoinACK',
    'UDP',

    # Application Layer Protocols
    'FTP',
    'HTTPv1',
    'HTTPv2',
    'HTTPv2_FrameType',
    'HTTPv2_UnassignedFrame', 'HTTPv2_DataFrame', 'HTTPv2_HeadersFrame', 'HTTPv2_PriorityFrame',
    'HTTPv2_RSTStreamFrame', 'HTTPv2_SettingsFrame', 'HTTPv2_PushPromiseFrame', 'HTTPv2_PingFrame',
    'HTTPv2_GoawayFrame', 'HTTPv2_WindowUpdateFrame', 'HTTPv2_ContinuationFrame',

    # PCAP file format
    'Header',
    'Frame',

    # misc protocols
    'NoPayload',
    'Raw',
]
