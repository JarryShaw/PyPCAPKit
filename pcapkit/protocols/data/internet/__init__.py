# -*- coding: utf-8 -*-
"""data models for internet layer protocols"""

# Authentication Header
from pcapkit.protocols.data.internet.ah import AH

# Host Identity Protocol
from pcapkit.protocols.data.internet.hip import HIP
from pcapkit.protocols.data.internet.hip import AckDataParameter as HIP_AckDataParameter
from pcapkit.protocols.data.internet.hip import ACKParameter as HIP_ACKParameter
from pcapkit.protocols.data.internet.hip import CertParameter as HIP_CertParameter
from pcapkit.protocols.data.internet.hip import Control as HIP_Control
from pcapkit.protocols.data.internet.hip import DHGroupListParameter as HIP_DHGroupListParameter
from pcapkit.protocols.data.internet.hip import DiffieHellmanParameter as HIP_DiffieHellmanParameter
from pcapkit.protocols.data.internet.hip import \
    EchoRequestSignedParameter as HIP_EchoRequestSignedParameter
from pcapkit.protocols.data.internet.hip import \
    EchoRequestUnsignedParameter as HIP_EchoRequestUnsignedParameter
from pcapkit.protocols.data.internet.hip import \
    EchoResponseSignedParameter as HIP_EchoResponseSignedParameter
from pcapkit.protocols.data.internet.hip import \
    EchoResponseUnsignedParameter as HIP_EchoResponseUnsignedParameter
from pcapkit.protocols.data.internet.hip import EncryptedParameter as HIP_EncryptedParameter
from pcapkit.protocols.data.internet.hip import ESPInfoParameter as HIP_ESPInfoParameter
from pcapkit.protocols.data.internet.hip import ESPTransformParameter as HIP_ESPTransformParameter
from pcapkit.protocols.data.internet.hip import Flags as HIP_Flags
from pcapkit.protocols.data.internet.hip import FromParameter as HIP_FromParameter
from pcapkit.protocols.data.internet.hip import HIPCipherParameter as HIP_HIPCipherParameter
from pcapkit.protocols.data.internet.hip import HIPMAC2Parameter as HIP_HIPMAC2Parameter
from pcapkit.protocols.data.internet.hip import HIPMACParameter as HIP_HIPMACParameter
from pcapkit.protocols.data.internet.hip import HIPSignature2Parameter as HIP_HIPSignature2Parameter
from pcapkit.protocols.data.internet.hip import HIPSignatureParameter as HIP_HIPSignatureParameter
from pcapkit.protocols.data.internet.hip import HIPTransformParameter as HIP_HIPTransformParameter
from pcapkit.protocols.data.internet.hip import \
    HIPTransportModeParameter as HIP_HIPTransportModeParameter
from pcapkit.protocols.data.internet.hip import HITSuiteListParameter as HIP_HITSuiteListParameter
from pcapkit.protocols.data.internet.hip import HostIdentity as HIP_HostIdentity
from pcapkit.protocols.data.internet.hip import HostIDParameter as HIP_HostIDParameter
from pcapkit.protocols.data.internet.hip import Lifetime as HIP_Lifetime
from pcapkit.protocols.data.internet.hip import Locator as HIP_Locator
from pcapkit.protocols.data.internet.hip import LocatorData as HIP_LocatorData
from pcapkit.protocols.data.internet.hip import LocatorSetParameter as HIP_LocatorSetParameter
from pcapkit.protocols.data.internet.hip import \
    NATTraversalModeParameter as HIP_NATTraversalModeParameter
from pcapkit.protocols.data.internet.hip import NotificationParameter as HIP_NotificationParameter
from pcapkit.protocols.data.internet.hip import OverlayIDParameter as HIP_OverlayIDParameter
from pcapkit.protocols.data.internet.hip import PayloadMICParameter as HIP_PayloadMICParameter
from pcapkit.protocols.data.internet.hip import PuzzleParameter as HIP_PuzzleParameter
from pcapkit.protocols.data.internet.hip import R1CounterParameter as HIP_R1CounterParameter
from pcapkit.protocols.data.internet.hip import RegFailedParameter as HIP_RegFailedParameter
from pcapkit.protocols.data.internet.hip import RegFromParameter as HIP_RegFromParameter
from pcapkit.protocols.data.internet.hip import RegInfoParameter as HIP_RegInfoParameter
from pcapkit.protocols.data.internet.hip import RegRequestParameter as HIP_RegRequestParameter
from pcapkit.protocols.data.internet.hip import RegResponseParameter as HIP_RegResponseParameter
from pcapkit.protocols.data.internet.hip import RelayFromParameter as HIP_RelayFromParameter
from pcapkit.protocols.data.internet.hip import RelayHMACParameter as HIP_RelayHMACParameter
from pcapkit.protocols.data.internet.hip import RelayToParameter as HIP_RelayToParameter
from pcapkit.protocols.data.internet.hip import RouteDstParameter as HIP_RouteDstParameter
from pcapkit.protocols.data.internet.hip import RouteViaParameter as HIP_RouteViaParameter
from pcapkit.protocols.data.internet.hip import RVSHMACParameter as HIP_RVSHMACParameter
from pcapkit.protocols.data.internet.hip import SeqDataParameter as HIP_SeqDataParameter
from pcapkit.protocols.data.internet.hip import SEQParameter as HIP_SEQParameter
from pcapkit.protocols.data.internet.hip import SolutionParameter as HIP_SolutionParameter
from pcapkit.protocols.data.internet.hip import TransactionIDParameter as HIP_TransactionIDParameter
from pcapkit.protocols.data.internet.hip import \
    TransactionPacingParameter as HIP_TransactionPacingParameter
from pcapkit.protocols.data.internet.hip import \
    TransportFormatListParameter as HIP_TransportFormatListParameter
from pcapkit.protocols.data.internet.hip import UnassignedParameter as HIP_UnassignedParameter

# Hop-by-Hop Options
from pcapkit.protocols.data.internet.hopopt import HOPOPT
from pcapkit.protocols.data.internet.hopopt import CALIPSOOption as HOPOPT_CALIPSOOption
from pcapkit.protocols.data.internet.hopopt import DFFFlags as HOPOPT_DFFFlags
from pcapkit.protocols.data.internet.hopopt import HomeAddressOption as HOPOPT_HomeAddressOption
from pcapkit.protocols.data.internet.hopopt import ILNPOption as HOPOPT_ILNPOption
from pcapkit.protocols.data.internet.hopopt import IPDFFOption as HOPOPT_IPDFFOption
from pcapkit.protocols.data.internet.hopopt import JumboPayloadOption as HOPOPT_JumboPayloadOption
from pcapkit.protocols.data.internet.hopopt import \
    LineIdentificationOption as HOPOPT_LineIdentificationOption
from pcapkit.protocols.data.internet.hopopt import MPLFlags as HOPOPT_MPLFlags
from pcapkit.protocols.data.internet.hopopt import MPLOption as HOPOPT_MPLOption
from pcapkit.protocols.data.internet.hopopt import PadOption as HOPOPT_PadOption
from pcapkit.protocols.data.internet.hopopt import PDMOption as HOPOPT_PDMOption
from pcapkit.protocols.data.internet.hopopt import \
    QuickStartReportOption as HOPOPT_QuickStartReportOption
from pcapkit.protocols.data.internet.hopopt import \
    QuickStartRequestOption as HOPOPT_QuickStartRequestOption
from pcapkit.protocols.data.internet.hopopt import RouterAlertOption as HOPOPT_RouterAlertOption
from pcapkit.protocols.data.internet.hopopt import RPLFlags as HOPOPT_RPLFlags
from pcapkit.protocols.data.internet.hopopt import RPLOption as HOPOPT_RPLOption
from pcapkit.protocols.data.internet.hopopt import \
    SMFHashBasedDPDOption as HOPOPT_SMFHashBasedDPDOption
from pcapkit.protocols.data.internet.hopopt import \
    SMFIdentificationBasedDPDOption as HOPOPT_SMFIdentificationBasedDPDOption
from pcapkit.protocols.data.internet.hopopt import \
    TunnelEncapsulationLimitOption as HOPOPT_TunnelEncapsulationLimitOption
from pcapkit.protocols.data.internet.hopopt import UnassignedOption as HOPOPT_UnassignedOption

# Internet Protocol version 4
from pcapkit.protocols.data.internet.ipv4 import EOOLOption as IPv4_EOOLOption
from pcapkit.protocols.data.internet.ipv4 import ESECOption as IPv4_ESECOption
from pcapkit.protocols.data.internet.ipv4 import Flags as IPv4_Flags
from pcapkit.protocols.data.internet.ipv4 import IPv4
from pcapkit.protocols.data.internet.ipv4 import LSROption as IPv4_LSROption
from pcapkit.protocols.data.internet.ipv4 import MTUPOption as IPv4_MTUPOption
from pcapkit.protocols.data.internet.ipv4 import MTUROption as IPv4_MTUROption
from pcapkit.protocols.data.internet.ipv4 import NOPOption as IPv4_NOPOption
from pcapkit.protocols.data.internet.ipv4 import OptionType as IPv4_OptionType
from pcapkit.protocols.data.internet.ipv4 import QSOption as IPv4_QSOption
from pcapkit.protocols.data.internet.ipv4 import \
    QuickStartReportOption as IPv4_QuickStartReportOption
from pcapkit.protocols.data.internet.ipv4 import \
    QuickStartRequestOption as IPv4_QuickStartRequestOption
from pcapkit.protocols.data.internet.ipv4 import RROption as IPv4_RROption
from pcapkit.protocols.data.internet.ipv4 import RTRALTOption as IPv4_RTRALTOption
from pcapkit.protocols.data.internet.ipv4 import SECOption as IPv4_SECOption
from pcapkit.protocols.data.internet.ipv4 import SIDOption as IPv4_SIDOption
from pcapkit.protocols.data.internet.ipv4 import SSROption as IPv4_SSROption
from pcapkit.protocols.data.internet.ipv4 import ToSField as IPv4_ToSField
from pcapkit.protocols.data.internet.ipv4 import TROption as IPv4_TROption
from pcapkit.protocols.data.internet.ipv4 import TSOption as IPv4_TSOption
from pcapkit.protocols.data.internet.ipv4 import UnassignedOption as IPv4_UnassignedOption

# Internet Protocol version 6
from pcapkit.protocols.data.internet.ipv6 import IPv6

# IPv6 Fragment Header
from pcapkit.protocols.data.internet.ipv6_frag import IPv6_Frag

# IPv6 Destination Options
from pcapkit.protocols.data.internet.ipv6_opts import CALIPSOOption as IPv6_Opts_CALIPSOOption
from pcapkit.protocols.data.internet.ipv6_opts import DFFFlags as IPv6_Opts_DFFFlags
from pcapkit.protocols.data.internet.ipv6_opts import \
    HomeAddressOption as IPv6_Opts_HomeAddressOption
from pcapkit.protocols.data.internet.ipv6_opts import ILNPOption as IPv6_Opts_ILNPOption
from pcapkit.protocols.data.internet.ipv6_opts import IPDFFOption as IPv6_Opts_IPDFFOption
from pcapkit.protocols.data.internet.ipv6_opts import IPv6_Opts
from pcapkit.protocols.data.internet.ipv6_opts import \
    JumboPayloadOption as IPv6_Opts_JumboPayloadOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    LineIdentificationOption as IPv6_Opts_LineIdentificationOption
from pcapkit.protocols.data.internet.ipv6_opts import MPLFlags as IPv6_Opts_MPLFlags
from pcapkit.protocols.data.internet.ipv6_opts import MPLOption as IPv6_Opts_MPLOption
from pcapkit.protocols.data.internet.ipv6_opts import PadOption as IPv6_Opts_PadOption
from pcapkit.protocols.data.internet.ipv6_opts import PDMOption as IPv6_Opts_PDMOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    QuickStartReportOption as IPv6_Opts_QuickStartReportOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    QuickStartRequestOption as IPv6_Opts_QuickStartRequestOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    RouterAlertOption as IPv6_Opts_RouterAlertOption
from pcapkit.protocols.data.internet.ipv6_opts import RPLFlags as IPv6_Opts_RPLFlags
from pcapkit.protocols.data.internet.ipv6_opts import RPLOption as IPv6_Opts_RPLOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    SMFHashBasedDPDOption as IPv6_Opts_SMFHashBasedDPDOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    SMFIdentificationBasedDPDOption as IPv6_Opts_SMFIdentificationBasedDPDOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    TunnelEncapsulationLimitOption as IPv6_Opts_TunnelEncapsulationLimitOption
from pcapkit.protocols.data.internet.ipv6_opts import UnassignedOption as IPv6_Opts_UnassignedOption

# IPv6 Routing Header
from pcapkit.protocols.data.internet.ipv6_route import RPL as IPv6_Route_RPL
from pcapkit.protocols.data.internet.ipv6_route import IPv6_Route
from pcapkit.protocols.data.internet.ipv6_route import SourceRoute as IPv6_Route_SourceRoute
from pcapkit.protocols.data.internet.ipv6_route import Type2 as IPv6_Route_Type2
from pcapkit.protocols.data.internet.ipv6_route import UnknownType as IPv6_Route_UnknownType

# Internetwork Packet Exchange
from pcapkit.protocols.data.internet.ipx import IPX
from pcapkit.protocols.data.internet.ipx import Address as IPX_Address

# Mobility Header
from pcapkit.protocols.data.internet.mh import MH
from pcapkit.protocols.data.internet.mh import \
    AlternateCareofAddressOption as MH_AlternateCareofAddressOption
from pcapkit.protocols.data.internet.mh import AuthOption as MH_AuthOption
from pcapkit.protocols.data.internet.mh import \
    BindingAcknowledgementMessage as MH_BindingAcknowledgementMessage
from pcapkit.protocols.data.internet.mh import \
    AuthorizationDataOption as MH_AuthorizationDataOption
from pcapkit.protocols.data.internet.mh import BindingErrorMessage as MH_BindingErrorMessage
from pcapkit.protocols.data.internet.mh import \
    BindingRefreshRequestMessage as MH_BindingRefreshRequestMessage
from pcapkit.protocols.data.internet.mh import BindingUpdateMessage as MH_BindingUpdateMessage
from pcapkit.protocols.data.internet.mh import BindingRefreshAdviceOption as MH_BindingRefreshAdviceOption
from pcapkit.protocols.data.internet.mh import CareofTestInitMessage as MH_CareofTestInitMessage
from pcapkit.protocols.data.internet.mh import CareofTestInitOption as MH_CareofTestInitOption
from pcapkit.protocols.data.internet.mh import CareofTestMessage as MH_CareofTestMessage
from pcapkit.protocols.data.internet.mh import CareofTestOption as MH_CareofTestOption
from pcapkit.protocols.data.internet.mh import CGAExtension as MH_CGAExtension
from pcapkit.protocols.data.internet.mh import CGAParameter as MH_CGAParameter
from pcapkit.protocols.data.internet.mh import CGAParametersOption as MH_CGAParametersOption
from pcapkit.protocols.data.internet.mh import \
    CGAParametersRequestOption as MH_CGAParametersRequestOption
from pcapkit.protocols.data.internet.mh import HomeTestInitMessage as MH_HomeTestInitMessage
from pcapkit.protocols.data.internet.mh import HomeTestMessage as MH_HomeTestMessage
from pcapkit.protocols.data.internet.mh import LinkLayerAddressOption as MH_LinkLayerAddressOption
from pcapkit.protocols.data.internet.mh import MesgIDOption as MH_MesgIDOption
from pcapkit.protocols.data.internet.mh import MNIDOption as MH_MNIDOption
from pcapkit.protocols.data.internet.mh import \
    MobileNetworkPrefixOption as MH_MobileNetworkPrefixOption
from pcapkit.protocols.data.internet.mh import MultiPrefixExtension as MH_MultiPrefixExtension
from pcapkit.protocols.data.internet.mh import NonceIndicesOption as MH_NonceIndicesOption
from pcapkit.protocols.data.internet.mh import Option as MH_Option
from pcapkit.protocols.data.internet.mh import PadOption as MH_PadOption
from pcapkit.protocols.data.internet.mh import \
    PermanentHomeKeygenTokenOption as MH_PermanentHomeKeygenTokenOption
from pcapkit.protocols.data.internet.mh import SignatureOption as MH_SignatureOption
from pcapkit.protocols.data.internet.mh import UnassignedOption as MH_UnassignedOption
from pcapkit.protocols.data.internet.mh import UnknownExtension as MH_UnknownExtension
from pcapkit.protocols.data.internet.mh import UnknownMessage as MH_UnknownMessage

__all__ = [
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
    'HOPOPT_SMFHashBasedDPDOption', 'HOPOPT_PDMOption', 'HOPOPT_QuickStartRequestOption',
    'HOPOPT_QuickStartReportOption', 'HOPOPT_RPLOption', 'HOPOPT_MPLOption', 'HOPOPT_ILNPOption',
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
]
