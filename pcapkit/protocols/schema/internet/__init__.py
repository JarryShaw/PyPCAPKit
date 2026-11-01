# -*- coding: utf-8 -*-
"""header schema for internet layer protocols"""

# Authentication Header
from pcapkit.protocols.schema.internet.ah import AH

# Encapsulating Security Payload
from pcapkit.protocols.schema.internet.esp import ESP

# Host Identity Protocol
from pcapkit.protocols.schema.internet.hip import HIP
from pcapkit.protocols.schema.internet.hip import AckDataParameter as HIP_AckDataParameter
from pcapkit.protocols.schema.internet.hip import ACKParameter as HIP_ACKParameter
from pcapkit.protocols.schema.internet.hip import CertParameter as HIP_CertParameter
from pcapkit.protocols.schema.internet.hip import DHGroupListParameter as HIP_DHGroupListParameter
from pcapkit.protocols.schema.internet.hip import \
    DiffieHellmanParameter as HIP_DiffieHellmanParameter
from pcapkit.protocols.schema.internet.hip import \
    ECDSACurveHostIdentity as HIP_ECDSACurveHostIdentity
from pcapkit.protocols.schema.internet.hip import \
    ECDSALowCurveHostIdentity as HIP_ECDSALowCurveHostIdentity
from pcapkit.protocols.schema.internet.hip import \
    EchoRequestSignedParameter as HIP_EchoRequestSignedParameter
from pcapkit.protocols.schema.internet.hip import \
    EchoRequestUnsignedParameter as HIP_EchoRequestUnsignedParameter
from pcapkit.protocols.schema.internet.hip import \
    EchoResponseSignedParameter as HIP_EchoResponseSignedParameter
from pcapkit.protocols.schema.internet.hip import \
    EchoResponseUnsignedParameter as HIP_EchoResponseUnsignedParameter
from pcapkit.protocols.schema.internet.hip import \
    EdDSACurveHostIdentity as HIP_EdDSACurveHostIdentity
from pcapkit.protocols.schema.internet.hip import EncryptedParameter as HIP_EncryptedParameter
from pcapkit.protocols.schema.internet.hip import ESPInfoParameter as HIP_ESPInfoParameter
from pcapkit.protocols.schema.internet.hip import ESPTransformParameter as HIP_ESPTransformParameter
from pcapkit.protocols.schema.internet.hip import FromParameter as HIP_FromParameter
from pcapkit.protocols.schema.internet.hip import HIPCipherParameter as HIP_HIPCipherParameter
from pcapkit.protocols.schema.internet.hip import HIPMAC2Parameter as HIP_HIPMAC2Parameter
from pcapkit.protocols.schema.internet.hip import HIPMACParameter as HIP_HIPMACParameter
from pcapkit.protocols.schema.internet.hip import \
    HIPSignature2Parameter as HIP_HIPSignature2Parameter
from pcapkit.protocols.schema.internet.hip import HIPSignatureParameter as HIP_HIPSignatureParameter
from pcapkit.protocols.schema.internet.hip import HIPTransformParameter as HIP_HIPTransformParameter
from pcapkit.protocols.schema.internet.hip import \
    HIPTransportModeParameter as HIP_HIPTransportModeParameter
from pcapkit.protocols.schema.internet.hip import HITSuiteListParameter as HIP_HITSuiteListParameter
from pcapkit.protocols.schema.internet.hip import HostIdentity as HIP_HostIdentity
from pcapkit.protocols.schema.internet.hip import HostIDParameter as HIP_HostIDParameter
from pcapkit.protocols.schema.internet.hip import Locator as HIP_Locator
from pcapkit.protocols.schema.internet.hip import LocatorData as HIP_LocatorData
from pcapkit.protocols.schema.internet.hip import LocatorSetParameter as HIP_LocatorSetParameter
from pcapkit.protocols.schema.internet.hip import \
    NATTraversalModeParameter as HIP_NATTraversalModeParameter
from pcapkit.protocols.schema.internet.hip import NotificationParameter as HIP_NotificationParameter
from pcapkit.protocols.schema.internet.hip import OverlayIDParameter as HIP_OverlayIDParameter
from pcapkit.protocols.schema.internet.hip import OverlayTTLParameter as HIP_OverlayTTLParameter
from pcapkit.protocols.schema.internet.hip import PayloadMICParameter as HIP_PayloadMICParameter
from pcapkit.protocols.schema.internet.hip import PuzzleParameter as HIP_PuzzleParameter
from pcapkit.protocols.schema.internet.hip import R1CounterParameter as HIP_R1CounterParameter
from pcapkit.protocols.schema.internet.hip import RegFailedParameter as HIP_RegFailedParameter
from pcapkit.protocols.schema.internet.hip import RegFromParameter as HIP_RegFromParameter
from pcapkit.protocols.schema.internet.hip import RegInfoParameter as HIP_RegInfoParameter
from pcapkit.protocols.schema.internet.hip import RegRequestParameter as HIP_RegRequestParameter
from pcapkit.protocols.schema.internet.hip import RegResponseParameter as HIP_RegResponseParameter
from pcapkit.protocols.schema.internet.hip import RelayFromParameter as HIP_RelayFromParameter
from pcapkit.protocols.schema.internet.hip import RelayHMACParameter as HIP_RelayHMACParameter
from pcapkit.protocols.schema.internet.hip import RelayToParameter as HIP_RelayToParameter
from pcapkit.protocols.schema.internet.hip import RouteDstParameter as HIP_RouteDstParameter
from pcapkit.protocols.schema.internet.hip import RouteViaParameter as HIP_RouteViaParameter
from pcapkit.protocols.schema.internet.hip import RVSHMACParameter as HIP_RVSHMACParameter
from pcapkit.protocols.schema.internet.hip import SeqDataParameter as HIP_SeqDataParameter
from pcapkit.protocols.schema.internet.hip import SEQParameter as HIP_SEQParameter
from pcapkit.protocols.schema.internet.hip import SolutionParameter as HIP_SolutionParameter
from pcapkit.protocols.schema.internet.hip import \
    TransactionIDParameter as HIP_TransactionIDParameter
from pcapkit.protocols.schema.internet.hip import \
    TransactionPacingParameter as HIP_TransactionPacingParameter
from pcapkit.protocols.schema.internet.hip import \
    TransportFormatListParameter as HIP_TransportFormatListParameter
from pcapkit.protocols.schema.internet.hip import UnassignedParameter as HIP_UnassignedParameter
from pcapkit.protocols.schema.internet.hip import ViaRVSParameter as HIP_ViaRVSParameter

# Hop-by-Hop Options
from pcapkit.protocols.schema.internet.hopopt import HOPOPT
from pcapkit.protocols.schema.internet.hopopt import CALIPSOOption as HOPOPT_CALIPSOOption
from pcapkit.protocols.schema.internet.hopopt import HomeAddressOption as HOPOPT_HomeAddressOption
from pcapkit.protocols.schema.internet.hopopt import ILNPOption as HOPOPT_ILNPOption
from pcapkit.protocols.schema.internet.hopopt import IPDFFOption as HOPOPT_IPDFFOption
from pcapkit.protocols.schema.internet.hopopt import JumboPayloadOption as HOPOPT_JumboPayloadOption
from pcapkit.protocols.schema.internet.hopopt import \
    LineIdentificationOption as HOPOPT_LineIdentificationOption
from pcapkit.protocols.schema.internet.hopopt import MPLOption as HOPOPT_MPLOption
from pcapkit.protocols.schema.internet.hopopt import PadOption as HOPOPT_PadOption
from pcapkit.protocols.schema.internet.hopopt import PDMOption as HOPOPT_PDMOption
from pcapkit.protocols.schema.internet.hopopt import QuickStartOption as HOPOPT_QuickStartOption
from pcapkit.protocols.schema.internet.hopopt import \
    QuickStartReportOption as HOPOPT_QuickStartReportOption
from pcapkit.protocols.schema.internet.hopopt import \
    QuickStartRequestOption as HOPOPT_QuickStartRequestOption
from pcapkit.protocols.schema.internet.hopopt import RouterAlertOption as HOPOPT_RouterAlertOption
from pcapkit.protocols.schema.internet.hopopt import RPLOption as HOPOPT_RPLOption
from pcapkit.protocols.schema.internet.hopopt import SMFDPDOption as HOPOPT_SMFDPDOption
from pcapkit.protocols.schema.internet.hopopt import \
    SMFHashBasedDPDOption as HOPOPT_SMFHashBasedDPDOption
from pcapkit.protocols.schema.internet.hopopt import \
    SMFIdentificationBasedDPDOption as HOPOPT_SMFIdentificationBasedDPDOption
from pcapkit.protocols.schema.internet.hopopt import \
    TunnelEncapsulationLimitOption as HOPOPT_TunnelEncapsulationLimitOption
from pcapkit.protocols.schema.internet.hopopt import UnassignedOption as HOPOPT_UnassignedOption

# Internet Control Message Protocol
from pcapkit.protocols.schema.internet.icmpv4 import ICMPv4
from pcapkit.protocols.schema.internet.icmpv4 import \
    DestinationUnreachable as ICMPv4_DestinationUnreachable
from pcapkit.protocols.schema.internet.icmpv4 import Echo as ICMPv4_Echo
from pcapkit.protocols.schema.internet.icmpv4 import ICMPv4Type as ICMPv4_ICMPv4Type
from pcapkit.protocols.schema.internet.icmpv4 import ParameterProblem as ICMPv4_ParameterProblem
from pcapkit.protocols.schema.internet.icmpv4 import TimeExceeded as ICMPv4_TimeExceeded
from pcapkit.protocols.schema.internet.icmpv4 import Unknown as ICMPv4_Unknown

# Internet Control Message Protocol for IPv6
from pcapkit.protocols.schema.internet.icmpv6 import ICMPv6
from pcapkit.protocols.schema.internet.icmpv6 import \
    DestinationUnreachable as ICMPv6_DestinationUnreachable
from pcapkit.protocols.schema.internet.icmpv6 import Echo as ICMPv6_Echo
from pcapkit.protocols.schema.internet.icmpv6 import ICMPv6Type as ICMPv6_ICMPv6Type
from pcapkit.protocols.schema.internet.icmpv6 import PacketTooBig as ICMPv6_PacketTooBig
from pcapkit.protocols.schema.internet.icmpv6 import ParameterProblem as ICMPv6_ParameterProblem
from pcapkit.protocols.schema.internet.icmpv6 import TimeExceeded as ICMPv6_TimeExceeded
from pcapkit.protocols.schema.internet.icmpv6 import Unknown as ICMPv6_Unknown

# Internet Group Management Protocol
from pcapkit.protocols.schema.internet.igmp import IGMP
from pcapkit.protocols.schema.internet.igmpv3 import GroupRecord as IGMPv3_GroupRecord
from pcapkit.protocols.schema.internet.igmpv3 import IGMPv3
from pcapkit.protocols.schema.internet.igmpv3 import Query as IGMPv3_Query
from pcapkit.protocols.schema.internet.igmpv3 import QueryExtension as IGMPv3_QueryExtension
from pcapkit.protocols.schema.internet.igmpv3 import Report as IGMPv3_Report

# Internet Protocol version 4
from pcapkit.protocols.schema.internet.ipv4 import EOOLOption as IPv4_EOOLOption
from pcapkit.protocols.schema.internet.ipv4 import ESECOption as IPv4_ESECOption
from pcapkit.protocols.schema.internet.ipv4 import IPv4
from pcapkit.protocols.schema.internet.ipv4 import LSROption as IPv4_LSROption
from pcapkit.protocols.schema.internet.ipv4 import MTUPOption as IPv4_MTUPOption
from pcapkit.protocols.schema.internet.ipv4 import MTUROption as IPv4_MTUROption
from pcapkit.protocols.schema.internet.ipv4 import NOPOption as IPv4_NOPOption
from pcapkit.protocols.schema.internet.ipv4 import Option as IPv4_Option
from pcapkit.protocols.schema.internet.ipv4 import QSOption as IPv4_QSOption
from pcapkit.protocols.schema.internet.ipv4 import \
    QuickStartReportOption as IPv4_QuickStartReportOption
from pcapkit.protocols.schema.internet.ipv4 import \
    QuickStartRequestOption as IPv4_QuickStartRequestOption
from pcapkit.protocols.schema.internet.ipv4 import RROption as IPv4_RROption
from pcapkit.protocols.schema.internet.ipv4 import RTRALTOption as IPv4_RTRALTOption
from pcapkit.protocols.schema.internet.ipv4 import SECOption as IPv4_SECOption
from pcapkit.protocols.schema.internet.ipv4 import SIDOption as IPv4_SIDOption
from pcapkit.protocols.schema.internet.ipv4 import SSROption as IPv4_SSROption
from pcapkit.protocols.schema.internet.ipv4 import TROption as IPv4_TROption
from pcapkit.protocols.schema.internet.ipv4 import TSOption as IPv4_TSOption
from pcapkit.protocols.schema.internet.ipv4 import UnassignedOption as IPv4_UnassignedOption

# Internet Protocol version 6
from pcapkit.protocols.schema.internet.ipv6 import IPv6

# IPv6 Fragment Header
from pcapkit.protocols.schema.internet.ipv6_frag import IPv6_Frag

# IPv6 Extension Header (generic)
from pcapkit.protocols.schema.internet.ipv6_ext import IPv6_Ext

# IPv6 Destination Options
from pcapkit.protocols.schema.internet.ipv6_opts import CALIPSOOption as IPv6_Opts_CALIPSOOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    HomeAddressOption as IPv6_Opts_HomeAddressOption
from pcapkit.protocols.schema.internet.ipv6_opts import ILNPOption as IPv6_Opts_ILNPOption
from pcapkit.protocols.schema.internet.ipv6_opts import IPDFFOption as IPv6_Opts_IPDFFOption
from pcapkit.protocols.schema.internet.ipv6_opts import IPv6_Opts
from pcapkit.protocols.schema.internet.ipv6_opts import \
    JumboPayloadOption as IPv6_Opts_JumboPayloadOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    LineIdentificationOption as IPv6_Opts_LineIdentificationOption
from pcapkit.protocols.schema.internet.ipv6_opts import MPLOption as IPv6_Opts_MPLOption
from pcapkit.protocols.schema.internet.ipv6_opts import PadOption as IPv6_Opts_PadOption
from pcapkit.protocols.schema.internet.ipv6_opts import PDMOption as IPv6_Opts_PDMOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    QuickStartOption as IPv6_Opts_QuickStartOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    QuickStartReportOption as IPv6_Opts_QuickStartReportOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    QuickStartRequestOption as IPv6_Opts_QuickStartRequestOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    RouterAlertOption as IPv6_Opts_RouterAlertOption
from pcapkit.protocols.schema.internet.ipv6_opts import RPLOption as IPv6_Opts_RPLOption
from pcapkit.protocols.schema.internet.ipv6_opts import SMFDPDOption as IPv6_Opts_SMFDPDOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    SMFHashBasedDPDOption as IPv6_Opts_SMFHashBasedDPDOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    SMFIdentificationBasedDPDOption as IPv6_Opts_SMFIdentificationBasedDPDOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    TunnelEncapsulationLimitOption as IPv6_Opts_TunnelEncapsulationLimitOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    UnassignedOption as IPv6_Opts_UnassignedOption

# IPv6 Routing Header
from pcapkit.protocols.schema.internet.ipv6_route import RPL as IPv6_Route_RPL
from pcapkit.protocols.schema.internet.ipv6_route import IPv6_Route
from pcapkit.protocols.schema.internet.ipv6_route import RoutingType as IPv6_Route_RoutingType
from pcapkit.protocols.schema.internet.ipv6_route import SourceRoute as IPv6_Route_SourceRoute
from pcapkit.protocols.schema.internet.ipv6_route import Type2 as IPv6_Route_Type2
from pcapkit.protocols.schema.internet.ipv6_route import UnknownType as IPv6_Route_UnknownType

# Internetwork Packet Exchange
from pcapkit.protocols.schema.internet.ipx import IPX

# Mobility Header
from pcapkit.protocols.schema.internet.mh import MH
from pcapkit.protocols.schema.internet.mh import \
    AccessNetworkIdentifierOption as MH_AccessNetworkIdentifierOption
from pcapkit.protocols.schema.internet.mh import \
    AccessTechnologyTypeOption as MH_AccessTechnologyTypeOption
from pcapkit.protocols.schema.internet.mh import \
    ActiveMulticastSubscriptionIPv4Option as MH_ActiveMulticastSubscriptionIPv4Option
from pcapkit.protocols.schema.internet.mh import \
    ActiveMulticastSubscriptionIPv6Option as MH_ActiveMulticastSubscriptionIPv6Option
from pcapkit.protocols.schema.internet.mh import \
    AllocationRetentionPriorityAttribute as MH_AllocationRetentionPriorityAttribute
from pcapkit.protocols.schema.internet.mh import \
    AlternateCareofAddressOption as MH_AlternateCareofAddressOption
from pcapkit.protocols.schema.internet.mh import \
    AlternateIPv4CareofAddressOption as MH_AlternateIPv4CareofAddressOption
from pcapkit.protocols.schema.internet.mh import AnchoredPrefixOption as MH_AnchoredPrefixOption
from pcapkit.protocols.schema.internet.mh import \
    ANICivicLocationSuboption as MH_ANICivicLocationSuboption
from pcapkit.protocols.schema.internet.mh import \
    ANIGeoLocationSuboption as MH_ANIGeoLocationSuboption
from pcapkit.protocols.schema.internet.mh import \
    ANIMAGGroupIdentifierSuboption as MH_ANIMAGGroupIdentifierSuboption
from pcapkit.protocols.schema.internet.mh import \
    ANINetworkIdentifierSuboption as MH_ANINetworkIdentifierSuboption
from pcapkit.protocols.schema.internet.mh import \
    ANIOperatorIdentifierSuboption as MH_ANIOperatorIdentifierSuboption
from pcapkit.protocols.schema.internet.mh import ANISuboption as MH_ANISuboption
from pcapkit.protocols.schema.internet.mh import \
    ANIUpdateTimerSuboption as MH_ANIUpdateTimerSuboption
from pcapkit.protocols.schema.internet.mh import AuthOption as MH_AuthOption
from pcapkit.protocols.schema.internet.mh import \
    AuthorizationDataOption as MH_AuthorizationDataOption
from pcapkit.protocols.schema.internet.mh import BADFOption as MH_BADFOption
from pcapkit.protocols.schema.internet.mh import BIDReferenceSuboption as MH_BIDReferenceSuboption
from pcapkit.protocols.schema.internet.mh import \
    BindingAcknowledgementMessage as MH_BindingAcknowledgementMessage
from pcapkit.protocols.schema.internet.mh import BindingErrorMessage as MH_BindingErrorMessage
from pcapkit.protocols.schema.internet.mh import \
    BindingIdentifierOption as MH_BindingIdentifierOption
from pcapkit.protocols.schema.internet.mh import \
    BindingRefreshAdviceOption as MH_BindingRefreshAdviceOption
from pcapkit.protocols.schema.internet.mh import \
    BindingRefreshRequestMessage as MH_BindingRefreshRequestMessage
from pcapkit.protocols.schema.internet.mh import \
    BindingReregistrationControlSuboption as MH_BindingReregistrationControlSuboption
from pcapkit.protocols.schema.internet.mh import \
    BindingRevocationMessage as MH_BindingRevocationMessage
from pcapkit.protocols.schema.internet.mh import BindingUpdateMessage as MH_BindingUpdateMessage
from pcapkit.protocols.schema.internet.mh import BitRateAttribute as MH_BitRateAttribute
from pcapkit.protocols.schema.internet.mh import CareofTestInitMessage as MH_CareofTestInitMessage
from pcapkit.protocols.schema.internet.mh import CareofTestInitOption as MH_CareofTestInitOption
from pcapkit.protocols.schema.internet.mh import CareofTestMessage as MH_CareofTestMessage
from pcapkit.protocols.schema.internet.mh import CareofTestOption as MH_CareofTestOption
from pcapkit.protocols.schema.internet.mh import CGAExtension as MH_CGAExtension
from pcapkit.protocols.schema.internet.mh import CGAParameter as MH_CGAParameter
from pcapkit.protocols.schema.internet.mh import CGAParametersOption as MH_CGAParametersOption
from pcapkit.protocols.schema.internet.mh import \
    CGAParametersRequestOption as MH_CGAParametersRequestOption
from pcapkit.protocols.schema.internet.mh import ContextRequestOption as MH_ContextRequestOption
from pcapkit.protocols.schema.internet.mh import DelegatedMNPOption as MH_DelegatedMNPOption
from pcapkit.protocols.schema.internet.mh import \
    DLIFLinkLayerAddressOption as MH_DLIFLinkLayerAddressOption
from pcapkit.protocols.schema.internet.mh import \
    DLIFLinkLocalAddressOption as MH_DLIFLinkLocalAddressOption
from pcapkit.protocols.schema.internet.mh import DNSUpdateOption as MH_DNSUpdateOption
from pcapkit.protocols.schema.internet.mh import \
    DynamicIPMulticastSelectorOption as MH_DynamicIPMulticastSelectorOption
from pcapkit.protocols.schema.internet.mh import ExperimentalExtension as MH_ExperimentalExtension
from pcapkit.protocols.schema.internet.mh import ExperimentalMessage as MH_ExperimentalMessage
from pcapkit.protocols.schema.internet.mh import \
    ExperimentalMobilityOption as MH_ExperimentalMobilityOption
from pcapkit.protocols.schema.internet.mh import \
    FastBindingAcknowledgmentMessage as MH_FastBindingAcknowledgmentMessage
from pcapkit.protocols.schema.internet.mh import \
    FastBindingUpdateMessage as MH_FastBindingUpdateMessage
from pcapkit.protocols.schema.internet.mh import \
    FastNeighborAdvertisementMessage as MH_FastNeighborAdvertisementMessage
from pcapkit.protocols.schema.internet.mh import \
    FlowBindingActionSuboption as MH_FlowBindingActionSuboption
from pcapkit.protocols.schema.internet.mh import FlowBindingMessage as MH_FlowBindingMessage
from pcapkit.protocols.schema.internet.mh import \
    FlowIdentificationOption as MH_FlowIdentificationOption
from pcapkit.protocols.schema.internet.mh import \
    FlowIdentificationSuboption as MH_FlowIdentificationSuboption
from pcapkit.protocols.schema.internet.mh import FlowSummaryOption as MH_FlowSummaryOption
from pcapkit.protocols.schema.internet.mh import GREKeyOption as MH_GREKeyOption
from pcapkit.protocols.schema.internet.mh import HandoffIndicatorOption as MH_HandoffIndicatorOption
from pcapkit.protocols.schema.internet.mh import \
    HandoverAcknowledgeMessage as MH_HandoverAcknowledgeMessage
from pcapkit.protocols.schema.internet.mh import \
    HandoverInitiateMessage as MH_HandoverInitiateMessage
from pcapkit.protocols.schema.internet.mh import \
    HeartbeatControlSuboption as MH_HeartbeatControlSuboption
from pcapkit.protocols.schema.internet.mh import HeartbeatMessage as MH_HeartbeatMessage
from pcapkit.protocols.schema.internet.mh import HomeAgentSwitchMessage as MH_HomeAgentSwitchMessage
from pcapkit.protocols.schema.internet.mh import \
    HomeNetworkPrefixOption as MH_HomeNetworkPrefixOption
from pcapkit.protocols.schema.internet.mh import HomeTestInitMessage as MH_HomeTestInitMessage
from pcapkit.protocols.schema.internet.mh import HomeTestMessage as MH_HomeTestMessage
from pcapkit.protocols.schema.internet.mh import \
    IPv4AddressAcknowledgementOption as MH_IPv4AddressAcknowledgementOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4CareofAddressOption as MH_IPv4CareofAddressOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4DefaultRouterAddressOption as MH_IPv4DefaultRouterAddressOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4DHCPSupportModeOption as MH_IPv4DHCPSupportModeOption
from pcapkit.protocols.schema.internet.mh import IPv4HomeAddressOption as MH_IPv4HomeAddressOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4HomeAddressReplyOption as MH_IPv4HomeAddressReplyOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4HomeAddressRequestOption as MH_IPv4HomeAddressRequestOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4TrafficOffloadSelectorOption as MH_IPv4TrafficOffloadSelectorOption
from pcapkit.protocols.schema.internet.mh import \
    IPv6AddressPrefixOption as MH_IPv6AddressPrefixOption
from pcapkit.protocols.schema.internet.mh import LinkLayerAddressOption as MH_LinkLayerAddressOption
from pcapkit.protocols.schema.internet.mh import LinkLocalAddressOption as MH_LinkLocalAddressOption
from pcapkit.protocols.schema.internet.mh import LMAAddressOption as MH_LMAAddressOption
from pcapkit.protocols.schema.internet.mh import \
    LMAControlledMAGParametersOption as MH_LMAControlledMAGParametersOption
from pcapkit.protocols.schema.internet.mh import \
    LMAControlledMAGSuboption as MH_LMAControlledMAGSuboption
from pcapkit.protocols.schema.internet.mh import \
    LMAUserPlaneAddressOption as MH_LMAUserPlaneAddressOption
from pcapkit.protocols.schema.internet.mh import LoadInformationOption as MH_LoadInformationOption
from pcapkit.protocols.schema.internet.mh import \
    LocalizedRoutingAcknowledgmentMessage as MH_LocalizedRoutingAcknowledgmentMessage
from pcapkit.protocols.schema.internet.mh import \
    LocalizedRoutingInitiationMessage as MH_LocalizedRoutingInitiationMessage
from pcapkit.protocols.schema.internet.mh import LocalPrefixOption as MH_LocalPrefixOption
from pcapkit.protocols.schema.internet.mh import MAGIdentifierOption as MH_MAGIdentifierOption
from pcapkit.protocols.schema.internet.mh import MAGIPv6AddressOption as MH_MAGIPv6AddressOption
from pcapkit.protocols.schema.internet.mh import \
    MAGMultipathBindingOption as MH_MAGMultipathBindingOption
from pcapkit.protocols.schema.internet.mh import MesgIDOption as MH_MesgIDOption
from pcapkit.protocols.schema.internet.mh import \
    MNGroupIdentifierOption as MH_MNGroupIdentifierOption
from pcapkit.protocols.schema.internet.mh import MNIDOption as MH_MNIDOption
from pcapkit.protocols.schema.internet.mh import MNLLAIIDOption as MH_MNLLAIIDOption
from pcapkit.protocols.schema.internet.mh import MNLLIdentifierOption as MH_MNLLIdentifierOption
from pcapkit.protocols.schema.internet.mh import \
    MobileNetworkPrefixOption as MH_MobileNetworkPrefixOption
from pcapkit.protocols.schema.internet.mh import \
    MulticastAcknowledgementOption as MH_MulticastAcknowledgementOption
from pcapkit.protocols.schema.internet.mh import \
    MulticastMobilityOption as MH_MulticastMobilityOption
from pcapkit.protocols.schema.internet.mh import MultiPrefixExtension as MH_MultiPrefixExtension
from pcapkit.protocols.schema.internet.mh import NATDetectionOption as MH_NATDetectionOption
from pcapkit.protocols.schema.internet.mh import NonceIndicesOption as MH_NonceIndicesOption
from pcapkit.protocols.schema.internet.mh import Option as MH_Option
from pcapkit.protocols.schema.internet.mh import Packet as MH_Packet
from pcapkit.protocols.schema.internet.mh import \
    PadFlowIdentificationSuboption as MH_PadFlowIdentificationSuboption
from pcapkit.protocols.schema.internet.mh import PadOption as MH_PadOption
from pcapkit.protocols.schema.internet.mh import \
    PermanentHomeKeygenTokenOption as MH_PermanentHomeKeygenTokenOption
from pcapkit.protocols.schema.internet.mh import \
    PerSessionBitRateAttribute as MH_PerSessionBitRateAttribute
from pcapkit.protocols.schema.internet.mh import PreviousMAAROption as MH_PreviousMAAROption
from pcapkit.protocols.schema.internet.mh import QoSAttribute as MH_QoSAttribute
from pcapkit.protocols.schema.internet.mh import \
    QoSTrafficSelectorAttribute as MH_QoSTrafficSelectorAttribute
from pcapkit.protocols.schema.internet.mh import \
    QoSVendorSpecificAttribute as MH_QoSVendorSpecificAttribute
from pcapkit.protocols.schema.internet.mh import QualityOfServiceOption as MH_QualityOfServiceOption
from pcapkit.protocols.schema.internet.mh import \
    RedirectCapabilityOption as MH_RedirectCapabilityOption
from pcapkit.protocols.schema.internet.mh import RedirectOption as MH_RedirectOption
from pcapkit.protocols.schema.internet.mh import RestartCounterOption as MH_RestartCounterOption
from pcapkit.protocols.schema.internet.mh import ServiceSelectionOption as MH_ServiceSelectionOption
from pcapkit.protocols.schema.internet.mh import ServingMAAROption as MH_ServingMAAROption
from pcapkit.protocols.schema.internet.mh import SignatureOption as MH_SignatureOption
from pcapkit.protocols.schema.internet.mh import \
    SubscriptionQueryMessage as MH_SubscriptionQueryMessage
from pcapkit.protocols.schema.internet.mh import \
    SubscriptionResponseMessage as MH_SubscriptionResponseMessage
from pcapkit.protocols.schema.internet.mh import \
    TargetCareofAddressSuboption as MH_TargetCareofAddressSuboption
from pcapkit.protocols.schema.internet.mh import TimestampOption as MH_TimestampOption
from pcapkit.protocols.schema.internet.mh import \
    TrafficSelectorSuboption as MH_TrafficSelectorSuboption
from pcapkit.protocols.schema.internet.mh import TransientBindingOption as MH_TransientBindingOption
from pcapkit.protocols.schema.internet.mh import UnassignedANISuboption as MH_UnassignedANISuboption
from pcapkit.protocols.schema.internet.mh import \
    UnassignedFlowIdentificationSuboption as MH_UnassignedFlowIdentificationSuboption
from pcapkit.protocols.schema.internet.mh import \
    UnassignedLMAControlledMAGSuboption as MH_UnassignedLMAControlledMAGSuboption
from pcapkit.protocols.schema.internet.mh import UnassignedOption as MH_UnassignedOption
from pcapkit.protocols.schema.internet.mh import UnassignedQoSAttribute as MH_UnassignedQoSAttribute
from pcapkit.protocols.schema.internet.mh import UnknownExtension as MH_UnknownExtension
from pcapkit.protocols.schema.internet.mh import UnknownMessage as MH_UnknownMessage
from pcapkit.protocols.schema.internet.mh import \
    UpdateNotificationAcknowledgementMessage as MH_UpdateNotificationAcknowledgementMessage
from pcapkit.protocols.schema.internet.mh import \
    UpdateNotificationMessage as MH_UpdateNotificationMessage
from pcapkit.protocols.schema.internet.mh import VendorSpecificOption as MH_VendorSpecificOption

__all__ = [
    # Authentication Header
    'AH',

    # Encapsulating Security Payload
    'ESP',

    # Host Identity Protocol
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
    'HIP_RelayToParameter', 'HIP_OverlayTTLParameter', 'HIP_RouteViaParameter',
    'HIP_FromParameter', 'HIP_RVSHMACParameter', 'HIP_ViaRVSParameter',
    'HIP_RelayHMACParameter',

    # Hop-by-Hop Options
    'HOPOPT',
    'HOPOPT_SMFDPDOption', 'HOPOPT_QuickStartOption',
    'HOPOPT_UnassignedOption', 'HOPOPT_PadOption', 'HOPOPT_TunnelEncapsulationLimitOption',
    'HOPOPT_RouterAlertOption', 'HOPOPT_CALIPSOOption', 'HOPOPT_SMFIdentificationBasedDPDOption',
    'HOPOPT_SMFHashBasedDPDOption', 'HOPOPT_PDMOption', 'HOPOPT_QuickStartRequestOption',
    'HOPOPT_QuickStartReportOption', 'HOPOPT_RPLOption', 'HOPOPT_MPLOption', 'HOPOPT_ILNPOption',
    'HOPOPT_LineIdentificationOption', 'HOPOPT_JumboPayloadOption', 'HOPOPT_HomeAddressOption',
    'HOPOPT_IPDFFOption',

    # Internet Control Message Protocol
    'ICMPv4',
    'ICMPv4_ICMPv4Type',
    'ICMPv4_Unknown', 'ICMPv4_Echo', 'ICMPv4_DestinationUnreachable', 'ICMPv4_TimeExceeded',
    'ICMPv4_ParameterProblem',

    # Internet Control Message Protocol for IPv6
    'ICMPv6',
    'ICMPv6_ICMPv6Type',
    'ICMPv6_Unknown', 'ICMPv6_DestinationUnreachable', 'ICMPv6_PacketTooBig', 'ICMPv6_TimeExceeded',
    'ICMPv6_ParameterProblem', 'ICMPv6_Echo',

    # Internet Group Management Protocol
    'IGMP', 'IGMPv3', 'IGMPv3_Query', 'IGMPv3_QueryExtension', 'IGMPv3_Report',
    'IGMPv3_GroupRecord',

    # Internet Protocol version 4
    'IPv4',
    'IPv4_Option',
    'IPv4_UnassignedOption', 'IPv4_EOOLOption', 'IPv4_NOPOption',
    'IPv4_SECOption', 'IPv4_LSROption', 'IPv4_TSOption',
    'IPv4_ESECOption', 'IPv4_RROption', 'IPv4_SIDOption',
    'IPv4_SSROption', 'IPv4_MTUPOption', 'IPv4_MTUROption',
    'IPv4_TROption', 'IPv4_RTRALTOption', 'IPv4_QSOption',
    'IPv4_QuickStartRequestOption', 'IPv4_QuickStartReportOption',

    # IPv6 Fragment Header
    'IPv6_Frag',

    # IPv6 Extension Header (generic)
    'IPv6_Ext',

    # IPv6 Destination Options
    'IPv6_Opts',
    'IPv6_Opts_SMFDPDOption', 'IPv6_Opts_QuickStartOption',
    'IPv6_Opts_UnassignedOption', 'IPv6_Opts_PadOption', 'IPv6_Opts_TunnelEncapsulationLimitOption',
    'IPv6_Opts_RouterAlertOption', 'IPv6_Opts_CALIPSOOption', 'IPv6_Opts_SMFIdentificationBasedDPDOption',
    'IPv6_Opts_SMFHashBasedDPDOption', 'IPv6_Opts_PDMOption', 'IPv6_Opts_QuickStartRequestOption',
    'IPv6_Opts_QuickStartReportOption', 'IPv6_Opts_RPLOption', 'IPv6_Opts_MPLOption', 'IPv6_Opts_ILNPOption',
    'IPv6_Opts_LineIdentificationOption', 'IPv6_Opts_JumboPayloadOption', 'IPv6_Opts_HomeAddressOption',
    'IPv6_Opts_IPDFFOption',

    # IPv6 Routing Header
    'IPv6_Route',
    'IPv6_Route_RoutingType',
    'IPv6_Route_UnknownType', 'IPv6_Route_SourceRoute', 'IPv6_Route_Type2', 'IPv6_Route_RPL',

    # IPv6
    'IPv6',

    # IPX
    'IPX',

    # Mobility Header
    'MH',
    'MH_Packet',
    'MH_UnknownMessage', 'MH_BindingRefreshRequestMessage', 'MH_HomeTestInitMessage', 'MH_CareofTestInitMessage',
    'MH_HomeTestMessage', 'MH_CareofTestMessage', 'MH_BindingUpdateMessage', 'MH_BindingAcknowledgementMessage',
    'MH_BindingErrorMessage', 'MH_FastBindingUpdateMessage', 'MH_FastBindingAcknowledgmentMessage',
    'MH_FastNeighborAdvertisementMessage', 'MH_ExperimentalMessage', 'MH_HandoverInitiateMessage',
    'MH_HandoverAcknowledgeMessage', 'MH_HeartbeatMessage', 'MH_HomeAgentSwitchMessage', 'MH_BindingRevocationMessage',
    'MH_LocalizedRoutingInitiationMessage', 'MH_LocalizedRoutingAcknowledgmentMessage', 'MH_UpdateNotificationMessage',
    'MH_UpdateNotificationAcknowledgementMessage', 'MH_FlowBindingMessage', 'MH_SubscriptionQueryMessage',
    'MH_SubscriptionResponseMessage',
    'MH_Option',
    'MH_UnassignedOption', 'MH_PadOption', 'MH_BindingRefreshAdviceOption', 'MH_AlternateCareofAddressOption',
    'MH_NonceIndicesOption', 'MH_AuthorizationDataOption', 'MH_MobileNetworkPrefixOption', 'MH_LinkLayerAddressOption',
    'MH_MNIDOption', 'MH_AuthOption', 'MH_MesgIDOption', 'MH_CGAParametersRequestOption', 'MH_CGAParametersOption',
    'MH_SignatureOption', 'MH_PermanentHomeKeygenTokenOption', 'MH_CareofTestInitOption', 'MH_CareofTestOption',
    'MH_ExperimentalMobilityOption', 'MH_BADFOption', 'MH_IPv6AddressPrefixOption', 'MH_HomeNetworkPrefixOption',
    'MH_HandoffIndicatorOption', 'MH_AccessTechnologyTypeOption', 'MH_MNLLIdentifierOption',
    'MH_LinkLocalAddressOption', 'MH_TimestampOption', 'MH_RestartCounterOption', 'MH_DNSUpdateOption',
    'MH_VendorSpecificOption', 'MH_ServiceSelectionOption', 'MH_IPv4HomeAddressOption',
    'MH_IPv4AddressAcknowledgementOption', 'MH_NATDetectionOption', 'MH_IPv4CareofAddressOption', 'MH_GREKeyOption',
    'MH_BindingIdentifierOption', 'MH_IPv4HomeAddressRequestOption', 'MH_IPv4HomeAddressReplyOption',
    'MH_IPv4DefaultRouterAddressOption', 'MH_IPv4DHCPSupportModeOption', 'MH_ContextRequestOption',
    'MH_LMAAddressOption', 'MH_MNLLAIIDOption', 'MH_TransientBindingOption', 'MH_FlowSummaryOption',
    'MH_FlowIdentificationOption', 'MH_RedirectCapabilityOption', 'MH_RedirectOption', 'MH_LoadInformationOption',
    'MH_AlternateIPv4CareofAddressOption', 'MH_MNGroupIdentifierOption', 'MH_MAGIPv6AddressOption',
    'MH_AccessNetworkIdentifierOption', 'MH_IPv4TrafficOffloadSelectorOption', 'MH_DynamicIPMulticastSelectorOption',
    'MH_DelegatedMNPOption', 'MH_ActiveMulticastSubscriptionIPv4Option', 'MH_ActiveMulticastSubscriptionIPv6Option',
    'MH_QualityOfServiceOption', 'MH_LMAUserPlaneAddressOption', 'MH_MulticastMobilityOption',
    'MH_MulticastAcknowledgementOption', 'MH_LMAControlledMAGParametersOption', 'MH_MAGMultipathBindingOption',
    'MH_MAGIdentifierOption', 'MH_AnchoredPrefixOption', 'MH_LocalPrefixOption', 'MH_PreviousMAAROption',
    'MH_ServingMAAROption', 'MH_DLIFLinkLocalAddressOption', 'MH_DLIFLinkLayerAddressOption',
    'MH_FlowIdentificationSuboption',
    'MH_UnassignedFlowIdentificationSuboption', 'MH_PadFlowIdentificationSuboption', 'MH_BIDReferenceSuboption',
    'MH_TrafficSelectorSuboption', 'MH_FlowBindingActionSuboption', 'MH_TargetCareofAddressSuboption',
    'MH_ANISuboption',
    'MH_UnassignedANISuboption', 'MH_ANINetworkIdentifierSuboption', 'MH_ANIGeoLocationSuboption',
    'MH_ANIOperatorIdentifierSuboption', 'MH_ANICivicLocationSuboption', 'MH_ANIMAGGroupIdentifierSuboption',
    'MH_ANIUpdateTimerSuboption',
    'MH_QoSAttribute',
    'MH_UnassignedQoSAttribute', 'MH_BitRateAttribute', 'MH_PerSessionBitRateAttribute',
    'MH_AllocationRetentionPriorityAttribute', 'MH_QoSTrafficSelectorAttribute', 'MH_QoSVendorSpecificAttribute',
    'MH_LMAControlledMAGSuboption',
    'MH_UnassignedLMAControlledMAGSuboption', 'MH_BindingReregistrationControlSuboption',
    'MH_HeartbeatControlSuboption',
    'MH_CGAParameter',
    'MH_CGAExtension',
    'MH_UnknownExtension', 'MH_MultiPrefixExtension', 'MH_ExperimentalExtension',
]
