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
    'IPv4_ToSField', 'IPv4_Flags',
    'IPv4_OptionType',
    'IPv4_UnassignedOption', 'IPv4_EOOLOption', 'IPv4_NOPOption',
    'IPv4_SECOption', 'IPv4_LSROption', 'IPv4_TSOption',
    'IPv4_ESECOption', 'IPv4_RROption', 'IPv4_SIDOption',
    'IPv4_SSROption', 'IPv4_MTUPOption', 'IPv4_MTUROption',
    'IPv4_TROption', 'IPv4_RTRALTOption', 'IPv4_QSOption',
    'IPv4_QuickStartRequestOption', 'IPv4_QuickStartReportOption',
    'IPv6_Frag',
    'IPv6_Route',
    'IPv6_Route_UnknownType', 'IPv6_Route_SourceRoute', 'IPv6_Route_Type2', 'IPv6_Route_RPL',

    # Transport Layer Protocols

    # Application Layer Protocols

    # PCAP file format
    'Header',
    'Frame',

    # misc protocols
    'NoPayload',
    'Raw',
]
