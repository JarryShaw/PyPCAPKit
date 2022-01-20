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
from pcapkit.protocols.data.internet.hip import DeffieHellmanParameter as HIP_DeffieHellmanParameter
from pcapkit.protocols.data.internet.hip import DHGroupListParameter as HIP_DHGroupListParameter
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
from pcapkit.protocols.data.internet.hopopt import QuickStartOption as HOPOPT_QuickStartOption
from pcapkit.protocols.data.internet.hopopt import RouterAlterOption as HOPOPT_RouterAlterOption
from pcapkit.protocols.data.internet.hopopt import RPLFlags as HOPOPT_RPLFlags
from pcapkit.protocols.data.internet.hopopt import RPLOption as HOPOPT_RPLOption
from pcapkit.protocols.data.internet.hopopt import \
    SMFHashBasedDPDOption as HOPOPT_SMFHashBasedDPDOption
from pcapkit.protocols.data.internet.hopopt import \
    SMFIdentificationBasedDPDOption as HOPOPT_SMFIdentificationBasedDPDOption
from pcapkit.protocols.data.internet.hopopt import \
    TunnelEncapsulationLimitOption as HOPOPT_TunnelEncapsulationLimitOption
from pcapkit.protocols.data.internet.hopopt import UnassignedOption as HOPOPT_UnassignedOption

__all__ = [
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
    'HOPOPT_RouterAlterOption', 'HOPOPT_CALIPSOOption', 'HOPOPT_SMFIdentificationBasedDPDOption',
    'HOPOPT_SMFHashBasedDPDOption', 'HOPOPT_PDMOption', 'HOPOPT_QuickStartOption',
    'HOPOPT_RPLOption', 'HOPOPT_MPLOption', 'HOPOPT_ILNPOption',
    'HOPOPT_LineIdentificationOption', 'HOPOPT_JumboPayloadOption', 'HOPOPT_HomeAddressOption',
    'HOPOPT_IPDFFOption',
]
