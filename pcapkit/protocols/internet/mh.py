# -*- coding: utf-8 -*-
# pylint: disable=fixme
"""mobility header

:mod:`pcapkit.protocols.internet.mh` contains
:class:`~pcapkit.protocols.internet.mh.MH` only,
which implements extractor for Mobility Header
(MH) [*]_, whose structure is described as below:

======= ========= ================== ===============================
Octets      Bits        Name                    Description
======= ========= ================== ===============================
  0           0   ``mh.next``                 Next Header
  1           8   ``mh.length``               Header Length
  2          16   ``mh.type``                 Mobility Header Type
  3          24                               Reserved
  4          32   ``mh.chksum``               Checksum
  6          48   ``mh.data``                 Message Data
======= ========= ================== ===============================

.. [*] https://en.wikipedia.org/wiki/Mobile_IP#Changes_in_IPv6_for_Mobile_IPv6

"""
import collections
import datetime
import ipaddress
import math
from typing import TYPE_CHECKING, cast, overload

from aenum import IntEnum, extend_enum

from pcapkit.const.mh.access_type import AccessType as Enum_AccessType
from pcapkit.const.mh.ack_status_code import ACKStatusCode as Enum_ACKStatusCode
from pcapkit.const.mh.ani_suboption import ANISuboption as Enum_ANISuboption
from pcapkit.const.mh.auth_subtype import AuthSubtype as Enum_AuthSubtype
from pcapkit.const.mh.binding_ack_flag import BindingACKFlag as Enum_BindingACKFlag
from pcapkit.const.mh.binding_error import BindingError as Enum_BindingError
from pcapkit.const.mh.binding_revocation import BindingRevocation as Enum_BindingRevocation
from pcapkit.const.mh.binding_update_flag import BindingUpdateFlag as Enum_BindingUpdateFlag
from pcapkit.const.mh.cga_extension import CGAExtension as Enum_CGAExtension
from pcapkit.const.mh.cga_type import CGAType as Enum_CGAType
from pcapkit.const.mh.dhcp_support_mode import DHCPSupportMode as Enum_DHCPSupportMode
from pcapkit.const.mh.dns_status_code import DNSStatusCode as Enum_DNSStatusCode
from pcapkit.const.mh.dsmip6_tls_packet import DSMIP6TLSPacket as Enum_DSMIP6TLSPacket
from pcapkit.const.mh.dsmipv6_home_address import DSMIPv6HomeAddress as Enum_DSMIPv6HomeAddress
from pcapkit.const.mh.enumerating_algorithm import EnumeratingAlgorithm as Enum_EnumeratingAlgorithm
from pcapkit.const.mh.fb_ack_status import FlowBindingACKStatus as Enum_FlowBindingACKStatus
from pcapkit.const.mh.fb_action import FlowBindingAction as Enum_FlowBindingAction
from pcapkit.const.mh.fb_indication_trigger import \
    FlowBindingIndicationTrigger as Enum_FlowBindingIndicationTrigger
from pcapkit.const.mh.fb_type import FlowBindingType as Enum_FlowBindingType
from pcapkit.const.mh.flow_id_status import FlowIDStatus as Enum_FlowIDStatus
from pcapkit.const.mh.flow_id_suboption import FlowIDSuboption as Enum_FlowIDSuboption
from pcapkit.const.mh.handoff_type import HandoffType as Enum_HandoffType
from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag as Enum_HandoverACKFlag
from pcapkit.const.mh.handover_ack_status import HandoverACKStatus as Enum_HandoverACKStatus
from pcapkit.const.mh.handover_initiate_flag import \
    HandoverInitiateFlag as Enum_HandoverInitiateFlag
from pcapkit.const.mh.handover_initiate_status import \
    HandoverInitiateStatus as Enum_HandoverInitiateStatus
from pcapkit.const.mh.home_address_reply import HomeAddressReply as Enum_HomeAddressReply
from pcapkit.const.mh.lla_code import LLACode as Enum_LLACode
from pcapkit.const.mh.lma_mag_suboption import \
    LMAControlledMAGSuboption as Enum_LMAControlledMAGSuboption
from pcapkit.const.mh.mn_group_id import MNGroupID as Enum_MNGroupID
from pcapkit.const.mh.mn_id_subtype import MNIDSubtype as Enum_MNIDSubtype
from pcapkit.const.mh.operator_id import OperatorID as Enum_OperatorID
from pcapkit.const.mh.option import Option as Enum_Option
from pcapkit.const.mh.packet import Packet as Enum_Packet
from pcapkit.const.mh.qos_attribute import QoSAttribute as Enum_QoSAttribute
from pcapkit.const.mh.revocation_status_code import \
    RevocationStatusCode as Enum_RevocationStatusCode
from pcapkit.const.mh.revocation_trigger import RevocationTrigger as Enum_RevocationTrigger
from pcapkit.const.mh.status_code import StatusCode as Enum_StatusCode
from pcapkit.const.mh.traffic_selector import TrafficSelector as Enum_TrafficSelector
from pcapkit.const.mh.upa_status import \
    UpdateNotificationACKStatus as Enum_UpdateNotificationACKStatus
from pcapkit.const.mh.upn_reason import UpdateNotificationReason as Enum_UpdateNotificationReason
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.internet.mh import MH as Data_MH
from pcapkit.protocols.data.internet.mh import \
    AccessNetworkIdentifierOption as Data_AccessNetworkIdentifierOption
from pcapkit.protocols.data.internet.mh import \
    AccessTechnologyTypeOption as Data_AccessTechnologyTypeOption
from pcapkit.protocols.data.internet.mh import \
    ActiveMulticastSubscriptionIPv4Option as Data_ActiveMulticastSubscriptionIPv4Option
from pcapkit.protocols.data.internet.mh import \
    ActiveMulticastSubscriptionIPv6Option as Data_ActiveMulticastSubscriptionIPv6Option
from pcapkit.protocols.data.internet.mh import \
    AllocationRetentionPriorityAttribute as Data_AllocationRetentionPriorityAttribute
from pcapkit.protocols.data.internet.mh import \
    AlternateCareofAddressOption as Data_AlternateCareofAddressOption
from pcapkit.protocols.data.internet.mh import \
    AlternateIPv4CareofAddressOption as Data_AlternateIPv4CareofAddressOption
from pcapkit.protocols.data.internet.mh import AnchoredPrefixOption as Data_AnchoredPrefixOption
from pcapkit.protocols.data.internet.mh import \
    ANICivicLocationSuboption as Data_ANICivicLocationSuboption
from pcapkit.protocols.data.internet.mh import \
    ANIGeoLocationSuboption as Data_ANIGeoLocationSuboption
from pcapkit.protocols.data.internet.mh import \
    ANIMAGGroupIdentifierSuboption as Data_ANIMAGGroupIdentifierSuboption
from pcapkit.protocols.data.internet.mh import \
    ANINetworkIdentifierSuboption as Data_ANINetworkIdentifierSuboption
from pcapkit.protocols.data.internet.mh import \
    ANIOperatorIdentifierSuboption as Data_ANIOperatorIdentifierSuboption
from pcapkit.protocols.data.internet.mh import ANISuboption as Data_ANISuboption
from pcapkit.protocols.data.internet.mh import \
    ANIUpdateTimerSuboption as Data_ANIUpdateTimerSuboption
from pcapkit.protocols.data.internet.mh import AuthOption as Data_AuthOption
from pcapkit.protocols.data.internet.mh import \
    AuthorizationDataOption as Data_AuthorizationDataOption
from pcapkit.protocols.data.internet.mh import BADFOption as Data_BADFOption
from pcapkit.protocols.data.internet.mh import BIDReferenceSuboption as Data_BIDReferenceSuboption
from pcapkit.protocols.data.internet.mh import \
    BindingAcknowledgementMessage as Data_BindingAcknowledgementMessage
from pcapkit.protocols.data.internet.mh import BindingErrorMessage as Data_BindingErrorMessage
from pcapkit.protocols.data.internet.mh import \
    BindingIdentifierOption as Data_BindingIdentifierOption
from pcapkit.protocols.data.internet.mh import \
    BindingRefreshAdviceOption as Data_BindingRefreshAdviceOption
from pcapkit.protocols.data.internet.mh import \
    BindingRefreshRequestMessage as Data_BindingRefreshRequestMessage
from pcapkit.protocols.data.internet.mh import \
    BindingReregistrationControlSuboption as Data_BindingReregistrationControlSuboption
from pcapkit.protocols.data.internet.mh import \
    BindingRevocationMessage as Data_BindingRevocationMessage
from pcapkit.protocols.data.internet.mh import BindingUpdateMessage as Data_BindingUpdateMessage
from pcapkit.protocols.data.internet.mh import BitRateAttribute as Data_BitRateAttribute
from pcapkit.protocols.data.internet.mh import CareofTestInitMessage as Data_CareofTestInitMessage
from pcapkit.protocols.data.internet.mh import CareofTestInitOption as Data_CareofTestInitOption
from pcapkit.protocols.data.internet.mh import CareofTestMessage as Data_CareofTestMessage
from pcapkit.protocols.data.internet.mh import CareofTestOption as Data_CareofTestOption
from pcapkit.protocols.data.internet.mh import CGAExtension as Data_CGAExtension
from pcapkit.protocols.data.internet.mh import CGAParameter as Data_CGAParameter
from pcapkit.protocols.data.internet.mh import CGAParametersOption as Data_CGAParametersOption
from pcapkit.protocols.data.internet.mh import \
    CGAParametersRequestOption as Data_CGAParametersRequestOption
from pcapkit.protocols.data.internet.mh import ContextRequest as Data_ContextRequest
from pcapkit.protocols.data.internet.mh import ContextRequestOption as Data_ContextRequestOption
from pcapkit.protocols.data.internet.mh import DelegatedMNPOption as Data_DelegatedMNPOption
from pcapkit.protocols.data.internet.mh import \
    DLIFLinkLayerAddressOption as Data_DLIFLinkLayerAddressOption
from pcapkit.protocols.data.internet.mh import \
    DLIFLinkLocalAddressOption as Data_DLIFLinkLocalAddressOption
from pcapkit.protocols.data.internet.mh import DNSUpdateOption as Data_DNSUpdateOption
from pcapkit.protocols.data.internet.mh import \
    DynamicIPMulticastSelectorOption as Data_DynamicIPMulticastSelectorOption
from pcapkit.protocols.data.internet.mh import ExperimentalExtension as Data_ExperimentalExtension
from pcapkit.protocols.data.internet.mh import ExperimentalMessage as Data_ExperimentalMessage
from pcapkit.protocols.data.internet.mh import \
    ExperimentalMobilityOption as Data_ExperimentalMobilityOption
from pcapkit.protocols.data.internet.mh import \
    FastBindingAcknowledgmentMessage as Data_FastBindingAcknowledgmentMessage
from pcapkit.protocols.data.internet.mh import \
    FastBindingUpdateMessage as Data_FastBindingUpdateMessage
from pcapkit.protocols.data.internet.mh import \
    FastNeighborAdvertisementMessage as Data_FastNeighborAdvertisementMessage
from pcapkit.protocols.data.internet.mh import \
    FlowBindingActionSuboption as Data_FlowBindingActionSuboption
from pcapkit.protocols.data.internet.mh import FlowBindingMessage as Data_FlowBindingMessage
from pcapkit.protocols.data.internet.mh import \
    FlowIdentificationOption as Data_FlowIdentificationOption
from pcapkit.protocols.data.internet.mh import \
    FlowIdentificationSuboption as Data_FlowIdentificationSuboption
from pcapkit.protocols.data.internet.mh import FlowSummaryOption as Data_FlowSummaryOption
from pcapkit.protocols.data.internet.mh import GREKeyOption as Data_GREKeyOption
from pcapkit.protocols.data.internet.mh import HandoffIndicatorOption as Data_HandoffIndicatorOption
from pcapkit.protocols.data.internet.mh import \
    HandoverAcknowledgeMessage as Data_HandoverAcknowledgeMessage
from pcapkit.protocols.data.internet.mh import \
    HandoverInitiateMessage as Data_HandoverInitiateMessage
from pcapkit.protocols.data.internet.mh import \
    HeartbeatControlSuboption as Data_HeartbeatControlSuboption
from pcapkit.protocols.data.internet.mh import HeartbeatMessage as Data_HeartbeatMessage
from pcapkit.protocols.data.internet.mh import HomeAgentSwitchMessage as Data_HomeAgentSwitchMessage
from pcapkit.protocols.data.internet.mh import \
    HomeNetworkPrefixOption as Data_HomeNetworkPrefixOption
from pcapkit.protocols.data.internet.mh import HomeTestInitMessage as Data_HomeTestInitMessage
from pcapkit.protocols.data.internet.mh import HomeTestMessage as Data_HomeTestMessage
from pcapkit.protocols.data.internet.mh import \
    IPv4AddressAcknowledgementOption as Data_IPv4AddressAcknowledgementOption
from pcapkit.protocols.data.internet.mh import \
    IPv4CareofAddressOption as Data_IPv4CareofAddressOption
from pcapkit.protocols.data.internet.mh import \
    IPv4DefaultRouterAddressOption as Data_IPv4DefaultRouterAddressOption
from pcapkit.protocols.data.internet.mh import \
    IPv4DHCPSupportModeOption as Data_IPv4DHCPSupportModeOption
from pcapkit.protocols.data.internet.mh import IPv4HomeAddressOption as Data_IPv4HomeAddressOption
from pcapkit.protocols.data.internet.mh import \
    IPv4HomeAddressReplyOption as Data_IPv4HomeAddressReplyOption
from pcapkit.protocols.data.internet.mh import \
    IPv4HomeAddressRequestOption as Data_IPv4HomeAddressRequestOption
from pcapkit.protocols.data.internet.mh import \
    IPv4TrafficOffloadSelectorOption as Data_IPv4TrafficOffloadSelectorOption
from pcapkit.protocols.data.internet.mh import \
    IPv6AddressPrefixOption as Data_IPv6AddressPrefixOption
from pcapkit.protocols.data.internet.mh import LinkLayerAddressOption as Data_LinkLayerAddressOption
from pcapkit.protocols.data.internet.mh import LinkLocalAddressOption as Data_LinkLocalAddressOption
from pcapkit.protocols.data.internet.mh import LMAAddressOption as Data_LMAAddressOption
from pcapkit.protocols.data.internet.mh import \
    LMAControlledMAGParametersOption as Data_LMAControlledMAGParametersOption
from pcapkit.protocols.data.internet.mh import \
    LMAControlledMAGSuboption as Data_LMAControlledMAGSuboption
from pcapkit.protocols.data.internet.mh import \
    LMAUserPlaneAddressOption as Data_LMAUserPlaneAddressOption
from pcapkit.protocols.data.internet.mh import LoadInformationOption as Data_LoadInformationOption
from pcapkit.protocols.data.internet.mh import \
    LocalizedRoutingAcknowledgmentMessage as Data_LocalizedRoutingAcknowledgmentMessage
from pcapkit.protocols.data.internet.mh import \
    LocalizedRoutingInitiationMessage as Data_LocalizedRoutingInitiationMessage
from pcapkit.protocols.data.internet.mh import LocalPrefixOption as Data_LocalPrefixOption
from pcapkit.protocols.data.internet.mh import MAGIdentifierOption as Data_MAGIdentifierOption
from pcapkit.protocols.data.internet.mh import MAGIPv6AddressOption as Data_MAGIPv6AddressOption
from pcapkit.protocols.data.internet.mh import \
    MAGMultipathBindingOption as Data_MAGMultipathBindingOption
from pcapkit.protocols.data.internet.mh import MesgIDOption as Data_MesgIDOption
from pcapkit.protocols.data.internet.mh import \
    MNGroupIdentifierOption as Data_MNGroupIdentifierOption
from pcapkit.protocols.data.internet.mh import MNIDOption as Data_MNIDOption
from pcapkit.protocols.data.internet.mh import MNLLAIIDOption as Data_MNLLAIIDOption
from pcapkit.protocols.data.internet.mh import MNLLIdentifierOption as Data_MNLLIdentifierOption
from pcapkit.protocols.data.internet.mh import \
    MobileNetworkPrefixOption as Data_MobileNetworkPrefixOption
from pcapkit.protocols.data.internet.mh import \
    MulticastAcknowledgementOption as Data_MulticastAcknowledgementOption
from pcapkit.protocols.data.internet.mh import \
    MulticastMobilityOption as Data_MulticastMobilityOption
from pcapkit.protocols.data.internet.mh import MultiPrefixExtension as Data_MultiPrefixExtension
from pcapkit.protocols.data.internet.mh import NATDetectionOption as Data_NATDetectionOption
from pcapkit.protocols.data.internet.mh import NonceIndicesOption as Data_NonceIndicesOption
from pcapkit.protocols.data.internet.mh import \
    PadFlowIdentificationSuboption as Data_PadFlowIdentificationSuboption
from pcapkit.protocols.data.internet.mh import PadOption as Data_PadOption
from pcapkit.protocols.data.internet.mh import \
    PermanentHomeKeygenTokenOption as Data_PermanentHomeKeygenTokenOption
from pcapkit.protocols.data.internet.mh import \
    PerSessionBitRateAttribute as Data_PerSessionBitRateAttribute
from pcapkit.protocols.data.internet.mh import PreviousMAAROption as Data_PreviousMAAROption
from pcapkit.protocols.data.internet.mh import QoSAttribute as Data_QoSAttribute
from pcapkit.protocols.data.internet.mh import \
    QoSTrafficSelectorAttribute as Data_QoSTrafficSelectorAttribute
from pcapkit.protocols.data.internet.mh import \
    QoSVendorSpecificAttribute as Data_QoSVendorSpecificAttribute
from pcapkit.protocols.data.internet.mh import QualityOfServiceOption as Data_QualityOfServiceOption
from pcapkit.protocols.data.internet.mh import \
    RedirectCapabilityOption as Data_RedirectCapabilityOption
from pcapkit.protocols.data.internet.mh import RedirectOption as Data_RedirectOption
from pcapkit.protocols.data.internet.mh import RestartCounterOption as Data_RestartCounterOption
from pcapkit.protocols.data.internet.mh import ServiceSelectionOption as Data_ServiceSelectionOption
from pcapkit.protocols.data.internet.mh import ServingMAAROption as Data_ServingMAAROption
from pcapkit.protocols.data.internet.mh import SignatureOption as Data_SignatureOption
from pcapkit.protocols.data.internet.mh import \
    SubscriptionQueryMessage as Data_SubscriptionQueryMessage
from pcapkit.protocols.data.internet.mh import \
    SubscriptionResponseMessage as Data_SubscriptionResponseMessage
from pcapkit.protocols.data.internet.mh import \
    TargetCareofAddressSuboption as Data_TargetCareofAddressSuboption
from pcapkit.protocols.data.internet.mh import TimestampOption as Data_TimestampOption
from pcapkit.protocols.data.internet.mh import \
    TrafficSelectorSuboption as Data_TrafficSelectorSuboption
from pcapkit.protocols.data.internet.mh import TransientBindingOption as Data_TransientBindingOption
from pcapkit.protocols.data.internet.mh import UnassignedANISuboption as Data_UnassignedANISuboption
from pcapkit.protocols.data.internet.mh import \
    UnassignedFlowIdentificationSuboption as Data_UnassignedFlowIdentificationSuboption
from pcapkit.protocols.data.internet.mh import \
    UnassignedLMAControlledMAGSuboption as Data_UnassignedLMAControlledMAGSuboption
from pcapkit.protocols.data.internet.mh import UnassignedOption as Data_UnassignedOption
from pcapkit.protocols.data.internet.mh import UnassignedQoSAttribute as Data_UnassignedQoSAttribute
from pcapkit.protocols.data.internet.mh import UnknownExtension as Data_UnknownExtension
from pcapkit.protocols.data.internet.mh import UnknownMessage as Data_UnknownMessage
from pcapkit.protocols.data.internet.mh import \
    UpdateNotificationAcknowledgementMessage as Data_UpdateNotificationAcknowledgementMessage
from pcapkit.protocols.data.internet.mh import \
    UpdateNotificationMessage as Data_UpdateNotificationMessage
from pcapkit.protocols.data.internet.mh import VendorSpecificOption as Data_VendorSpecificOption
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.schema.internet.mh import MH as Schema_MH
from pcapkit.protocols.schema.internet.mh import \
    AccessNetworkIdentifierOption as Schema_AccessNetworkIdentifierOption
from pcapkit.protocols.schema.internet.mh import \
    AccessTechnologyTypeOption as Schema_AccessTechnologyTypeOption
from pcapkit.protocols.schema.internet.mh import \
    ActiveMulticastSubscriptionIPv4Option as Schema_ActiveMulticastSubscriptionIPv4Option
from pcapkit.protocols.schema.internet.mh import \
    ActiveMulticastSubscriptionIPv6Option as Schema_ActiveMulticastSubscriptionIPv6Option
from pcapkit.protocols.schema.internet.mh import \
    AllocationRetentionPriorityAttribute as Schema_AllocationRetentionPriorityAttribute
from pcapkit.protocols.schema.internet.mh import \
    AlternateCareofAddressOption as Schema_AlternateCareofAddressOption
from pcapkit.protocols.schema.internet.mh import \
    AlternateIPv4CareofAddressOption as Schema_AlternateIPv4CareofAddressOption
from pcapkit.protocols.schema.internet.mh import AnchoredPrefixOption as Schema_AnchoredPrefixOption
from pcapkit.protocols.schema.internet.mh import \
    ANICivicLocationSuboption as Schema_ANICivicLocationSuboption
from pcapkit.protocols.schema.internet.mh import \
    ANIGeoLocationSuboption as Schema_ANIGeoLocationSuboption
from pcapkit.protocols.schema.internet.mh import \
    ANIMAGGroupIdentifierSuboption as Schema_ANIMAGGroupIdentifierSuboption
from pcapkit.protocols.schema.internet.mh import \
    ANINetworkIdentifierSuboption as Schema_ANINetworkIdentifierSuboption
from pcapkit.protocols.schema.internet.mh import \
    ANIOperatorIdentifierSuboption as Schema_ANIOperatorIdentifierSuboption
from pcapkit.protocols.schema.internet.mh import ANISuboption as Schema_ANISuboption
from pcapkit.protocols.schema.internet.mh import \
    ANIUpdateTimerSuboption as Schema_ANIUpdateTimerSuboption
from pcapkit.protocols.schema.internet.mh import AuthOption as Schema_AuthOption
from pcapkit.protocols.schema.internet.mh import \
    AuthorizationDataOption as Schema_AuthorizationDataOption
from pcapkit.protocols.schema.internet.mh import BADFOption as Schema_BADFOption
from pcapkit.protocols.schema.internet.mh import \
    BIDReferenceSuboption as Schema_BIDReferenceSuboption
from pcapkit.protocols.schema.internet.mh import \
    BindingAcknowledgementMessage as Schema_BindingAcknowledgementMessage
from pcapkit.protocols.schema.internet.mh import BindingErrorMessage as Schema_BindingErrorMessage
from pcapkit.protocols.schema.internet.mh import \
    BindingIdentifierOption as Schema_BindingIdentifierOption
from pcapkit.protocols.schema.internet.mh import \
    BindingRefreshAdviceOption as Schema_BindingRefreshAdviceOption
from pcapkit.protocols.schema.internet.mh import \
    BindingRefreshRequestMessage as Schema_BindingRefreshRequestMessage
from pcapkit.protocols.schema.internet.mh import \
    BindingReregistrationControlSuboption as Schema_BindingReregistrationControlSuboption
from pcapkit.protocols.schema.internet.mh import \
    BindingRevocationMessage as Schema_BindingRevocationMessage
from pcapkit.protocols.schema.internet.mh import BindingUpdateMessage as Schema_BindingUpdateMessage
from pcapkit.protocols.schema.internet.mh import BitRateAttribute as Schema_BitRateAttribute
from pcapkit.protocols.schema.internet.mh import \
    CareofTestInitMessage as Schema_CareofTestInitMessage
from pcapkit.protocols.schema.internet.mh import CareofTestInitOption as Schema_CareofTestInitOption
from pcapkit.protocols.schema.internet.mh import CareofTestMessage as Schema_CareofTestMessage
from pcapkit.protocols.schema.internet.mh import CareofTestOption as Schema_CareofTestOption
from pcapkit.protocols.schema.internet.mh import CGAExtension as Schema_CGAExtension
from pcapkit.protocols.schema.internet.mh import CGAParameter as Schema_CGAParameter
from pcapkit.protocols.schema.internet.mh import CGAParametersOption as Schema_CGAParametersOption
from pcapkit.protocols.schema.internet.mh import \
    CGAParametersRequestOption as Schema_CGAParametersRequestOption
from pcapkit.protocols.schema.internet.mh import ContextRequestOption as Schema_ContextRequestOption
from pcapkit.protocols.schema.internet.mh import DelegatedMNPOption as Schema_DelegatedMNPOption
from pcapkit.protocols.schema.internet.mh import \
    DLIFLinkLayerAddressOption as Schema_DLIFLinkLayerAddressOption
from pcapkit.protocols.schema.internet.mh import \
    DLIFLinkLocalAddressOption as Schema_DLIFLinkLocalAddressOption
from pcapkit.protocols.schema.internet.mh import DNSUpdateOption as Schema_DNSUpdateOption
from pcapkit.protocols.schema.internet.mh import \
    DynamicIPMulticastSelectorOption as Schema_DynamicIPMulticastSelectorOption
from pcapkit.protocols.schema.internet.mh import \
    ExperimentalExtension as Schema_ExperimentalExtension
from pcapkit.protocols.schema.internet.mh import ExperimentalMessage as Schema_ExperimentalMessage
from pcapkit.protocols.schema.internet.mh import \
    ExperimentalMobilityOption as Schema_ExperimentalMobilityOption
from pcapkit.protocols.schema.internet.mh import \
    FastBindingAcknowledgmentMessage as Schema_FastBindingAcknowledgmentMessage
from pcapkit.protocols.schema.internet.mh import \
    FastBindingUpdateMessage as Schema_FastBindingUpdateMessage
from pcapkit.protocols.schema.internet.mh import \
    FastNeighborAdvertisementMessage as Schema_FastNeighborAdvertisementMessage
from pcapkit.protocols.schema.internet.mh import \
    FlowBindingActionSuboption as Schema_FlowBindingActionSuboption
from pcapkit.protocols.schema.internet.mh import FlowBindingMessage as Schema_FlowBindingMessage
from pcapkit.protocols.schema.internet.mh import \
    FlowIdentificationOption as Schema_FlowIdentificationOption
from pcapkit.protocols.schema.internet.mh import \
    FlowIdentificationSuboption as Schema_FlowIdentificationSuboption
from pcapkit.protocols.schema.internet.mh import FlowSummaryOption as Schema_FlowSummaryOption
from pcapkit.protocols.schema.internet.mh import GREKeyOption as Schema_GREKeyOption
from pcapkit.protocols.schema.internet.mh import \
    HandoffIndicatorOption as Schema_HandoffIndicatorOption
from pcapkit.protocols.schema.internet.mh import \
    HandoverAcknowledgeMessage as Schema_HandoverAcknowledgeMessage
from pcapkit.protocols.schema.internet.mh import \
    HandoverInitiateMessage as Schema_HandoverInitiateMessage
from pcapkit.protocols.schema.internet.mh import \
    HeartbeatControlSuboption as Schema_HeartbeatControlSuboption
from pcapkit.protocols.schema.internet.mh import HeartbeatMessage as Schema_HeartbeatMessage
from pcapkit.protocols.schema.internet.mh import \
    HomeAgentSwitchMessage as Schema_HomeAgentSwitchMessage
from pcapkit.protocols.schema.internet.mh import \
    HomeNetworkPrefixOption as Schema_HomeNetworkPrefixOption
from pcapkit.protocols.schema.internet.mh import HomeTestInitMessage as Schema_HomeTestInitMessage
from pcapkit.protocols.schema.internet.mh import HomeTestMessage as Schema_HomeTestMessage
from pcapkit.protocols.schema.internet.mh import \
    IPv4AddressAcknowledgementOption as Schema_IPv4AddressAcknowledgementOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4CareofAddressOption as Schema_IPv4CareofAddressOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4DefaultRouterAddressOption as Schema_IPv4DefaultRouterAddressOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4DHCPSupportModeOption as Schema_IPv4DHCPSupportModeOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4HomeAddressOption as Schema_IPv4HomeAddressOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4HomeAddressReplyOption as Schema_IPv4HomeAddressReplyOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4HomeAddressRequestOption as Schema_IPv4HomeAddressRequestOption
from pcapkit.protocols.schema.internet.mh import \
    IPv4TrafficOffloadSelectorOption as Schema_IPv4TrafficOffloadSelectorOption
from pcapkit.protocols.schema.internet.mh import \
    IPv6AddressPrefixOption as Schema_IPv6AddressPrefixOption
from pcapkit.protocols.schema.internet.mh import \
    LinkLayerAddressOption as Schema_LinkLayerAddressOption
from pcapkit.protocols.schema.internet.mh import \
    LinkLocalAddressOption as Schema_LinkLocalAddressOption
from pcapkit.protocols.schema.internet.mh import LMAAddressOption as Schema_LMAAddressOption
from pcapkit.protocols.schema.internet.mh import \
    LMAControlledMAGParametersOption as Schema_LMAControlledMAGParametersOption
from pcapkit.protocols.schema.internet.mh import \
    LMAControlledMAGSuboption as Schema_LMAControlledMAGSuboption
from pcapkit.protocols.schema.internet.mh import \
    LMAUserPlaneAddressOption as Schema_LMAUserPlaneAddressOption
from pcapkit.protocols.schema.internet.mh import \
    LoadInformationOption as Schema_LoadInformationOption
from pcapkit.protocols.schema.internet.mh import \
    LocalizedRoutingAcknowledgmentMessage as Schema_LocalizedRoutingAcknowledgmentMessage
from pcapkit.protocols.schema.internet.mh import \
    LocalizedRoutingInitiationMessage as Schema_LocalizedRoutingInitiationMessage
from pcapkit.protocols.schema.internet.mh import LocalPrefixOption as Schema_LocalPrefixOption
from pcapkit.protocols.schema.internet.mh import MAGIdentifierOption as Schema_MAGIdentifierOption
from pcapkit.protocols.schema.internet.mh import MAGIPv6AddressOption as Schema_MAGIPv6AddressOption
from pcapkit.protocols.schema.internet.mh import \
    MAGMultipathBindingOption as Schema_MAGMultipathBindingOption
from pcapkit.protocols.schema.internet.mh import MesgIDOption as Schema_MesgIDOption
from pcapkit.protocols.schema.internet.mh import \
    MNGroupIdentifierOption as Schema_MNGroupIdentifierOption
from pcapkit.protocols.schema.internet.mh import MNIDOption as Schema_MNIDOption
from pcapkit.protocols.schema.internet.mh import MNLLAIIDOption as Schema_MNLLAIIDOption
from pcapkit.protocols.schema.internet.mh import MNLLIdentifierOption as Schema_MNLLIdentifierOption
from pcapkit.protocols.schema.internet.mh import \
    MobileNetworkPrefixOption as Schema_MobileNetworkPrefixOption
from pcapkit.protocols.schema.internet.mh import \
    MulticastAcknowledgementOption as Schema_MulticastAcknowledgementOption
from pcapkit.protocols.schema.internet.mh import \
    MulticastMobilityOption as Schema_MulticastMobilityOption
from pcapkit.protocols.schema.internet.mh import MultiPrefixExtension as Schema_MultiPrefixExtension
from pcapkit.protocols.schema.internet.mh import NATDetectionOption as Schema_NATDetectionOption
from pcapkit.protocols.schema.internet.mh import NonceIndicesOption as Schema_NonceIndicesOption
from pcapkit.protocols.schema.internet.mh import Packet as Schema_Packet
from pcapkit.protocols.schema.internet.mh import \
    PadFlowIdentificationSuboption as Schema_PadFlowIdentificationSuboption
from pcapkit.protocols.schema.internet.mh import PadOption as Schema_PadOption
from pcapkit.protocols.schema.internet.mh import \
    PermanentHomeKeygenTokenOption as Schema_PermanentHomeKeygenTokenOption
from pcapkit.protocols.schema.internet.mh import \
    PerSessionBitRateAttribute as Schema_PerSessionBitRateAttribute
from pcapkit.protocols.schema.internet.mh import PreviousMAAROption as Schema_PreviousMAAROption
from pcapkit.protocols.schema.internet.mh import QoSAttribute as Schema_QoSAttribute
from pcapkit.protocols.schema.internet.mh import \
    QoSTrafficSelectorAttribute as Schema_QoSTrafficSelectorAttribute
from pcapkit.protocols.schema.internet.mh import \
    QoSVendorSpecificAttribute as Schema_QoSVendorSpecificAttribute
from pcapkit.protocols.schema.internet.mh import \
    QualityOfServiceOption as Schema_QualityOfServiceOption
from pcapkit.protocols.schema.internet.mh import \
    RedirectCapabilityOption as Schema_RedirectCapabilityOption
from pcapkit.protocols.schema.internet.mh import RedirectOption as Schema_RedirectOption
from pcapkit.protocols.schema.internet.mh import RestartCounterOption as Schema_RestartCounterOption
from pcapkit.protocols.schema.internet.mh import \
    ServiceSelectionOption as Schema_ServiceSelectionOption
from pcapkit.protocols.schema.internet.mh import ServingMAAROption as Schema_ServingMAAROption
from pcapkit.protocols.schema.internet.mh import SignatureOption as Schema_SignatureOption
from pcapkit.protocols.schema.internet.mh import \
    SubscriptionQueryMessage as Schema_SubscriptionQueryMessage
from pcapkit.protocols.schema.internet.mh import \
    SubscriptionResponseMessage as Schema_SubscriptionResponseMessage
from pcapkit.protocols.schema.internet.mh import \
    TargetCareofAddressSuboption as Schema_TargetCareofAddressSuboption
from pcapkit.protocols.schema.internet.mh import TimestampOption as Schema_TimestampOption
from pcapkit.protocols.schema.internet.mh import \
    TrafficSelectorSuboption as Schema_TrafficSelectorSuboption
from pcapkit.protocols.schema.internet.mh import \
    TransientBindingOption as Schema_TransientBindingOption
from pcapkit.protocols.schema.internet.mh import \
    UnassignedANISuboption as Schema_UnassignedANISuboption
from pcapkit.protocols.schema.internet.mh import \
    UnassignedFlowIdentificationSuboption as Schema_UnassignedFlowIdentificationSuboption
from pcapkit.protocols.schema.internet.mh import \
    UnassignedLMAControlledMAGSuboption as Schema_UnassignedLMAControlledMAGSuboption
from pcapkit.protocols.schema.internet.mh import UnassignedOption as Schema_UnassignedOption
from pcapkit.protocols.schema.internet.mh import \
    UnassignedQoSAttribute as Schema_UnassignedQoSAttribute
from pcapkit.protocols.schema.internet.mh import UnknownExtension as Schema_UnknownExtension
from pcapkit.protocols.schema.internet.mh import UnknownMessage as Schema_UnknownMessage
from pcapkit.protocols.schema.internet.mh import \
    UpdateNotificationAcknowledgementMessage as Schema_UpdateNotificationAcknowledgementMessage
from pcapkit.protocols.schema.internet.mh import \
    UpdateNotificationMessage as Schema_UpdateNotificationMessage
from pcapkit.protocols.schema.internet.mh import VendorSpecificOption as Schema_VendorSpecificOption
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall
from pcapkit.utilities.warnings import ProtocolWarning, RegistryWarning, warn

if TYPE_CHECKING:
    from datetime import datetime as dt_type
    from datetime import timedelta
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address, IPv6Address, IPv6Network
    from typing import IO, Any, Callable, DefaultDict, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.corekit.multidict import OrderedMultiDict
    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.data.internet.mh import Option as Data_Option
    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.internet.mh import Option as Schema_Option
    from pcapkit.protocols.schema.internet.mh import Packet as Schema_Packet
    from pcapkit.protocols.schema.schema import Schema

    Option = OrderedMultiDict[Enum_Option, Data_Option]
    Extension = OrderedMultiDict[Enum_CGAExtension, Data_CGAExtension]

    FlowIDSuboption = OrderedMultiDict[Enum_FlowIDSuboption,
                                       Data_FlowIdentificationSuboption]
    ANISuboption = OrderedMultiDict[Enum_ANISuboption, Data_ANISuboption]
    QoSAttribute = OrderedMultiDict[Enum_QoSAttribute, Data_QoSAttribute]
    LMAControlledMAGSuboption = OrderedMultiDict[Enum_LMAControlledMAGSuboption,
                                                 Data_LMAControlledMAGSuboption]

    PacketParser = Callable[[Schema_Packet, NamedArg(Schema_MH, 'header')], Data_MH]
    PacketConstructor = Callable[[DefaultArg(Optional[Data_MH]),
                                 KwArg(Any)], Schema_Packet]

    OptionParser = Callable[[Schema_Option, NamedArg(Option, 'options')], Data_Option]
    OptionConstructor = Callable[[Enum_Option, DefaultArg(Optional[Data_Option]),
                                  KwArg(Any)], Schema_Option]

    ExtensionParser = Callable[[Schema_CGAExtension, NamedArg(Extension, 'extensions')], Data_CGAExtension]
    ExtensionConstructor = Callable[[Enum_CGAExtension, DefaultArg(Optional[Data_CGAExtension]),
                                     KwArg(Any)], Schema_CGAExtension]

__all__ = ['MH']


class NTPTimestamp(collections.namedtuple('NTPTimestamp', 'seconds fraction')):
    """NTP timestamp format, c.f., :rfc:`1305`."""

    __slots__ = ()

    #: Seconds since 1 January 1900.
    seconds: int
    #: Fraction of a second.
    fraction: int


class PMIPv6Timestamp(collections.namedtuple('PMIPv6Timestamp', 'seconds fraction')):
    """Proxy Mobile IPv6 timestamp format, c.f., :rfc:`5213#section-8.8`.

    Note:
        This is **not** an :rfc:`1305` NTP timestamp, which is why it is a type of
        its own rather than a reuse of :class:`NTPTimestamp`. It counts from the
        UNIX epoch rather than NTP's 1900 one, and splits its 64 bits 48/16
        rather than 32/32, so each field means something different in the two.

    """

    __slots__ = ()

    #: Seconds since 1 January 1970, in the leading 48 bits.
    seconds: int
    #: Fraction of a second, in units of 1/65536, in the trailing 16 bits.
    fraction: int


class FastBindingAcknowledgmentStatus(IntEnum):
    """[FastBindingAcknowledgmentStatus] Fast Binding Acknowledgment Status Codes.

    Status values of the fast binding acknowledgment (FBack) message, c.f.,
    :rfc:`5568#section-6.2.3`. Values below ``128`` indicate that the fast
    binding update was accepted by the receiving node, values of ``128`` and
    above that it was rejected.

    Note:
        :rfc:`5568#section-6.2.3` defines these values inline and IANA keeps no
        registry of them, so the enumeration lives here rather than in
        :mod:`pcapkit.const.mh`. It is also **not** interchangeable with the
        registered :class:`~pcapkit.const.mh.status_code.StatusCode`, since two
        of its values collide semantically: ``1`` means *NCoA is invalid* here
        but *accepted but prefix discovery necessary* there, and ``131`` means
        *incorrect interface identifier length* here but *home registration not
        supported* there.

    """

    #: Fast Binding Update accepted [:rfc:`5568#section-6.2.3`]
    Fast_Binding_Update_accepted = 0

    #: Fast Binding Update accepted but NCoA is invalid; use the NCoA supplied in
    #: the "alternate" care-of address option [:rfc:`5568#section-6.2.3`]
    Fast_Binding_Update_accepted_but_NCoA_is_invalid = 1

    #: Reason unspecified [:rfc:`5568#section-6.2.3`]
    Reason_unspecified = 128

    #: Administratively prohibited [:rfc:`5568#section-6.2.3`]
    Administratively_prohibited = 129

    #: Insufficient resources [:rfc:`5568#section-6.2.3`]
    Insufficient_resources = 130

    #: Incorrect interface identifier length [:rfc:`5568#section-6.2.3`]
    Incorrect_interface_identifier_length = 131

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'FastBindingAcknowledgmentStatus':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        """
        if isinstance(key, int):
            return FastBindingAcknowledgmentStatus(key)
        if key not in FastBindingAcknowledgmentStatus._member_map_:  # pylint: disable=no-member
            extend_enum(FastBindingAcknowledgmentStatus, key, default)
        return FastBindingAcknowledgmentStatus[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'FastBindingAcknowledgmentStatus':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        #: Unassigned
        return extend_enum(cls, 'Unassigned_%d' % value, value)


class IPv6AddressPrefixCode(IntEnum):
    """[IPv6AddressPrefixCode] Mobility Header IPv6 Address/Prefix Option Codes.

    Option codes of the mobility header IPv6 address/prefix option, which
    identify which address the option carries, c.f.,
    :rfc:`5568#section-6.4.2`.

    Note:
        :rfc:`5568#section-6.4.2` defines these values inline and IANA keeps no
        registry of them, so the enumeration lives here rather than in
        :mod:`pcapkit.const.mh`. The identical code space of the neighbor
        discovery IP address/prefix option of :rfc:`5568#section-6.4.1` is
        likewise unregistered.

    """

    #: Old Care-of Address [:rfc:`5568#section-6.4.2`]
    Old_Care_of_Address = 1

    #: New Care-of Address [:rfc:`5568#section-6.4.2`]
    New_Care_of_Address = 2

    #: NAR's IP address [:rfc:`5568#section-6.4.2`]
    NAR_IP_address = 3

    #: NAR's Prefix, sent in PrRtAdv; the prefix length field contains the number
    #: of valid leading bits in the prefix [:rfc:`5568#section-6.4.2`]
    NAR_Prefix = 4

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'IPv6AddressPrefixCode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        """
        if isinstance(key, int):
            return IPv6AddressPrefixCode(key)
        if key not in IPv6AddressPrefixCode._member_map_:  # pylint: disable=no-member
            extend_enum(IPv6AddressPrefixCode, key, default)
        return IPv6AddressPrefixCode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'IPv6AddressPrefixCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        #: Unassigned
        return extend_enum(cls, 'Unassigned_%d' % value, value)


class LocalizedRoutingStatus(IntEnum):
    """[LocalizedRoutingStatus] Localized Routing Acknowledgment Status Codes.

    Status values of the localized routing acknowledgment (LRA) message, c.f.,
    :rfc:`6705#section-10.2`. Values below ``128`` indicate that the initiation
    was processed successfully, values of ``128`` and above that it was rejected.

    Note:
        :rfc:`6705#section-10.2` defines these values inline and IANA keeps no
        registry of them -- neither a dedicated one nor entries in the general
        *Status Codes* registry -- so the enumeration lives here rather than in
        :mod:`pcapkit.const.mh`. It is **not** interchangeable with the
        registered :class:`~pcapkit.const.mh.status_code.StatusCode`, whose
        ``128`` and ``129`` mean something else entirely.

    """

    #: Success [:rfc:`6705#section-10.2`]
    Success = 0

    #: Localized Routing Not Allowed [:rfc:`6705#section-10.2`]
    Localized_Routing_Not_Allowed = 128

    #: MN Not Attached [:rfc:`6705#section-10.2`]
    MN_Not_Attached = 129

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'LocalizedRoutingStatus':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        """
        if isinstance(key, int):
            return LocalizedRoutingStatus(key)
        if key not in LocalizedRoutingStatus._member_map_:  # pylint: disable=no-member
            extend_enum(LocalizedRoutingStatus, key, default)
        return LocalizedRoutingStatus[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'LocalizedRoutingStatus':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        #: Unassigned
        return extend_enum(cls, 'Unassigned_%d' % value, value)


class LMAAddressCode(IntEnum):
    """[LMAAddressCode] Local Mobility Anchor Address Option Codes.

    Option codes of the local mobility anchor address option, which say which
    address family the option carries, c.f., :rfc:`5949#section-6.2.2`.

    Note:
        :rfc:`5949#section-6.2.2` defines these values inline and IANA keeps no
        registry of them, so the enumeration lives here rather than in
        :mod:`pcapkit.const.mh`.

    """

    #: Reserved [:rfc:`5949#section-6.2.2`]
    Reserved = 0

    #: IPv6 local mobility anchor address [:rfc:`5949#section-6.2.2`]
    IPv6_LMAA = 1

    #: IPv4 local mobility anchor address [:rfc:`5949#section-6.2.2`]
    IPv4_LMAA = 2

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'LMAAddressCode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        """
        if isinstance(key, int):
            return LMAAddressCode(key)
        if key not in LMAAddressCode._member_map_:  # pylint: disable=no-member
            extend_enum(LMAAddressCode, key, default)
        return LMAAddressCode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'LMAAddressCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        #: Unassigned
        return extend_enum(cls, 'Unassigned_%d' % value, value)


class MH(Internet[Data_MH, Schema_MH],
         schema=Schema_MH, data=Data_MH):
    """This class implements Mobility Header.

    This class currently supports parsing of the following MH message types,
    which are registered in the :attr:`self.__message__ <pcapkit.protocols.internet.mh.MH.__message__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Message Type
         - Message Parser
         - Message Constructor
       * - :attr:`~pcapkit.const.mh.packet.Packet.Binding_Refresh_Request`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_brr`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_brr`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Home_Test_Init`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_hoti`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_hoti`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Care_of_Test_Init`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_coti`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_coti`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Home_Test`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_hot`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_hot`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Care_of_Test`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_cot`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_cot`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Binding_Update`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_bu`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_bu`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Binding_Acknowledgement`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_ba`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_ba`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Binding_Error`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_be`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_be`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Fast_Binding_Update`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_fbu`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_fbu`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Fast_Binding_Acknowledgment`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_fback`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_fback`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Fast_Neighbor_Advertisement`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_fna`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_fna`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Experimental_Mobility_Header`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_emh`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_emh`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Home_Agent_Switch_Message`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_has`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_has`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Heartbeat_Message`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_hb`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_hb`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Handover_Initiate_Message`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_hi`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_hi`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Handover_Acknowledge_Message`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_hack`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_hack`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Binding_Revocation_Message`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_brm`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_brm`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Localized_Routing_Initiation`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_lri`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_lri`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Localized_Routing_Acknowledgment`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_lra`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_lra`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Update_Notification`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_upn`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_upn`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Update_Notification_Acknowledgement`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_upa`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_upa`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Flow_Binding_Message`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_fbm`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_fbm`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Subscription_Query`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_sq`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_sq`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Subscription_Response`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_sr`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_sr`

    This class currently supports parsing the following MH options, which are
    registered in the :attr:`self.__option__ <pcapkit.protocols.internet.mh.MH.__option__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Option Code
         - Option Parser
         - Option Constructor
       * - :attr:`~pcapkit.const.mh.option.Option.Pad1`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_pad`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_pad`
       * - :attr:`~pcapkit.const.mh.option.Option.PadN`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_pad`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_pad`
       * - :attr:`~pcapkit.const.mh.option.Option.Binding_Refresh_Advice`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_bra`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_bra`
       * - :attr:`~pcapkit.const.mh.option.Option.Alternate_Care_of_Address`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_aca`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_aca`
       * - :attr:`~pcapkit.const.mh.option.Option.Nonce_Indices`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ni`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ni`
       * - :attr:`~pcapkit.const.mh.option.Option.Authorization_Data`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_bad`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_bad`
       * - :attr:`~pcapkit.const.mh.option.Option.Mobile_Network_Prefix_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mnp`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mnp`
       * - :attr:`~pcapkit.const.mh.option.Option.Mobility_Header_Link_Layer_Address_option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_lla`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_lla`
       * - :attr:`~pcapkit.const.mh.option.Option.MN_ID_OPTION_TYPE`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mn_id`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mn_id`
       * - :attr:`~pcapkit.const.mh.option.Option.AUTH_OPTION_TYPE`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_auth`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_auth`
       * - :attr:`~pcapkit.const.mh.option.Option.MESG_ID_OPTION_TYPE`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mesg_id`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mesg_id`
       * - :attr:`~pcapkit.const.mh.option.Option.CGA_Parameters_Request`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_cga_pr`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_cga_pr`
       * - :attr:`~pcapkit.const.mh.option.Option.CGA_Parameters`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_cga_param`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_cga_param`
       * - :attr:`~pcapkit.const.mh.option.Option.Signature`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_signature`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_signature`
       * - :attr:`~pcapkit.const.mh.option.Option.Permanent_Home_Keygen_Token`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_phkt`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_phkt`
       * - :attr:`~pcapkit.const.mh.option.Option.Care_of_Test_Init`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ct_init`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ct_init`
       * - :attr:`~pcapkit.const.mh.option.Option.Care_of_Test`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ct`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ct`
       * - :attr:`~pcapkit.const.mh.option.Option.DNS_UPDATE_TYPE`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_dns`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_dns`
       * - :attr:`~pcapkit.const.mh.option.Option.Experimental_Mobility_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_exp`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_exp`
       * - :attr:`~pcapkit.const.mh.option.Option.Vendor_Specific_Mobility_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_vendor`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_vendor`
       * - :attr:`~pcapkit.const.mh.option.Option.Service_Selection_Mobility_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_service`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_service`
       * - :attr:`~pcapkit.const.mh.option.Option.Binding_Authorization_Data_for_FMIPv6`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_badf`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_badf`
       * - :attr:`~pcapkit.const.mh.option.Option.Home_Network_Prefix_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_hnp`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_hnp`
       * - :attr:`~pcapkit.const.mh.option.Option.Handoff_Indicator_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_hi`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_hi`
       * - :attr:`~pcapkit.const.mh.option.Option.Access_Technology_Type_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_att`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_att`
       * - :attr:`~pcapkit.const.mh.option.Option.Mobile_Node_Link_layer_Identifier_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mn_lli`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mn_lli`
       * - :attr:`~pcapkit.const.mh.option.Option.Link_local_Address_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_lla_addr`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_lla_addr`
       * - :attr:`~pcapkit.const.mh.option.Option.Timestamp_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_timestamp`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_timestamp`
       * - :attr:`~pcapkit.const.mh.option.Option.Restart_Counter`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_restart`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_restart`
       * - :attr:`~pcapkit.const.mh.option.Option.IPv4_Home_Address`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ipv4_hoa`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ipv4_hoa`
       * - :attr:`~pcapkit.const.mh.option.Option.IPv4_Address_Acknowledgement`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ipv4_ack`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ipv4_ack`
       * - :attr:`~pcapkit.const.mh.option.Option.NAT_Detection`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_nat`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_nat`
       * - :attr:`~pcapkit.const.mh.option.Option.IPv4_Care_of_Address`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ipv4_coa`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ipv4_coa`
       * - :attr:`~pcapkit.const.mh.option.Option.GRE_Key_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_gre`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_gre`
       * - :attr:`~pcapkit.const.mh.option.Option.Mobility_Header_IPv6_Address_Prefix`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ipv6_ap`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ipv6_ap`
       * - :attr:`~pcapkit.const.mh.option.Option.Binding_Identifier`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_bid`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_bid`
       * - :attr:`~pcapkit.const.mh.option.Option.IPv4_Home_Address_Request`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ipv4_hoa_req`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ipv4_hoa_req`
       * - :attr:`~pcapkit.const.mh.option.Option.IPv4_Home_Address_Reply`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ipv4_hoa_rep`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ipv4_hoa_rep`
       * - :attr:`~pcapkit.const.mh.option.Option.IPv4_Default_Router_Address`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ipv4_router`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ipv4_router`
       * - :attr:`~pcapkit.const.mh.option.Option.IPv4_DHCP_Support_Mode`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ipv4_dhcp`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ipv4_dhcp`
       * - :attr:`~pcapkit.const.mh.option.Option.Context_Request_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_cr`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_cr`
       * - :attr:`~pcapkit.const.mh.option.Option.Local_Mobility_Anchor_Address_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_lmaa`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_lmaa`
       * - :attr:`~pcapkit.const.mh.option.Option.Mobile_Node_Link_local_Address_Interface_Identifier_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mn_lla_iid`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mn_lla_iid`
       * - :attr:`~pcapkit.const.mh.option.Option.Transient_Binding`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_transient`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_transient`
       * - :attr:`~pcapkit.const.mh.option.Option.Flow_Summary_Mobility_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_fs`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_fs`
       * - :attr:`~pcapkit.const.mh.option.Option.Flow_Identification_Mobility_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_fid`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_fid`
       * - :attr:`~pcapkit.const.mh.option.Option.Redirect_Capability_Mobility_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_rc`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_rc`
       * - :attr:`~pcapkit.const.mh.option.Option.Redirect_Mobility_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_redirect`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_redirect`
       * - :attr:`~pcapkit.const.mh.option.Option.Load_Information_Mobility_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_load`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_load`
       * - :attr:`~pcapkit.const.mh.option.Option.Alternate_IPv4_Care_of_Address`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_alt_ipv4_coa`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_alt_ipv4_coa`
       * - :attr:`~pcapkit.const.mh.option.Option.Mobile_Node_Group_Identifier`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mn_group`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mn_group`
       * - :attr:`~pcapkit.const.mh.option.Option.MAG_IPv6_Address`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mag_addr`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mag_addr`
       * - :attr:`~pcapkit.const.mh.option.Option.Access_Network_Identifier`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ani`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ani`
       * - :attr:`~pcapkit.const.mh.option.Option.IPv4_Traffic_Offload_Selector`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_offload`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_offload`
       * - :attr:`~pcapkit.const.mh.option.Option.Dynamic_IP_Multicast_Selector`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mcast_sel`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mcast_sel`
       * - :attr:`~pcapkit.const.mh.option.Option.Delegated_Mobile_Network_Prefix`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_dmnp`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_dmnp`
       * - :attr:`~pcapkit.const.mh.option.Option.Active_Multicast_Subscription_IPv4`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ams4`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ams4`
       * - :attr:`~pcapkit.const.mh.option.Option.Active_Multicast_Subscription_IPv6`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ams6`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ams6`
       * - :attr:`~pcapkit.const.mh.option.Option.Quality_of_Service`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_qos`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_qos`
       * - :attr:`~pcapkit.const.mh.option.Option.LMA_User_Plane_Address`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_lma_up`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_lma_up`
       * - :attr:`~pcapkit.const.mh.option.Option.Multicast_Mobility_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mcast`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mcast`
       * - :attr:`~pcapkit.const.mh.option.Option.Multicast_Acknowledgement_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mcast_ack`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mcast_ack`
       * - :attr:`~pcapkit.const.mh.option.Option.LMA_Controlled_MAG_Parameters`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_lcmp`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_lcmp`
       * - :attr:`~pcapkit.const.mh.option.Option.MAG_Multipath_Binding`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mag_mp`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mag_mp`
       * - :attr:`~pcapkit.const.mh.option.Option.MAG_Identifier`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mag_id`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mag_id`
       * - :attr:`~pcapkit.const.mh.option.Option.Anchored_Prefix`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_anchored`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_anchored`
       * - :attr:`~pcapkit.const.mh.option.Option.Local_Prefix`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_local_prefix`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_local_prefix`
       * - :attr:`~pcapkit.const.mh.option.Option.Previous_MAAR`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_prev_maar`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_prev_maar`
       * - :attr:`~pcapkit.const.mh.option.Option.Serving_MAAR`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_serv_maar`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_serv_maar`
       * - :attr:`~pcapkit.const.mh.option.Option.DLIF_Link_Local_Address`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_dlif_lla`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_dlif_lla`
       * - :attr:`~pcapkit.const.mh.option.Option.DLIF_Link_Layer_Address`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_dlif_lladdr`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_dlif_lladdr`

    This class currently supports parsing of the following MH CGA extensions,
    which are registered in the :attr:`self.__extension__ <pcapkit.protocols.internet.mh.MH.__extension__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - CGA Extension Code
         - CGA Extension Parser
         - CGA Extension Constructor
       * - :attr:`~pcapkit.const.mh.cga_extension.CGAExtension.Multi_Prefix`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_ext_multiprefix`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_ext_multiprefix`
       * - :attr:`~pcapkit.const.mh.cga_extension.CGAExtension.Exp_FFFD`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_ext_exp`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_ext_exp`
       * - :attr:`~pcapkit.const.mh.cga_extension.CGAExtension.Exp_FFFE`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_ext_exp`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_ext_exp`
       * - :attr:`~pcapkit.const.mh.cga_extension.CGAExtension.Exp_FFFF`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_ext_exp`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_ext_exp`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[Enum_Packet, str | tuple[PacketParser, PacketConstructor]]:
    #: Message type to method mapping. Method names are expected to be referred
    #: to the class by ``_read_msg_${name}`` and/or ``_make_msg_${name}``,
    #: and if such name not found, the value should then be a method that can
    #: parse the message type by itself.
    __message__ = collections.defaultdict(
        lambda: 'unknown',
        {
            Enum_Packet.Binding_Refresh_Request: 'brr',
            Enum_Packet.Home_Test_Init: 'hoti',
            Enum_Packet.Care_of_Test_Init: 'coti',
            Enum_Packet.Home_Test: 'hot',
            Enum_Packet.Care_of_Test: 'cot',
            Enum_Packet.Binding_Update: 'bu',
            Enum_Packet.Binding_Acknowledgement: 'ba',
            Enum_Packet.Binding_Error: 'be',
            Enum_Packet.Fast_Binding_Update: 'fbu',
            Enum_Packet.Fast_Binding_Acknowledgment: 'fback',
            Enum_Packet.Fast_Neighbor_Advertisement: 'fna',
            Enum_Packet.Experimental_Mobility_Header: 'emh',
            Enum_Packet.Handover_Initiate_Message: 'hi',
            Enum_Packet.Handover_Acknowledge_Message: 'hack',
            Enum_Packet.Home_Agent_Switch_Message: 'has',
            Enum_Packet.Heartbeat_Message: 'hb',
            Enum_Packet.Binding_Revocation_Message: 'brm',
            Enum_Packet.Localized_Routing_Initiation: 'lri',
            Enum_Packet.Localized_Routing_Acknowledgment: 'lra',
            Enum_Packet.Update_Notification: 'upn',
            Enum_Packet.Update_Notification_Acknowledgement: 'upa',
            Enum_Packet.Flow_Binding_Message: 'fbm',
            Enum_Packet.Subscription_Query: 'sq',
            Enum_Packet.Subscription_Response: 'sr',
        },
    )  # type: DefaultDict[Enum_Packet | int, str | tuple[PacketParser, PacketConstructor]]

    #: DefaultDict[Enum_Option, str | tuple[OptionParser, OptionConstructor]]:
    #: Option type to method mapping. Method names are expected to be referred
    #: to the class by ``_read_option_${name}`` and/or ``_make_opt_${name}``,
    #: and if such name not found, the value should then be a method that can
    #: parse the option by itself.
    __option__ = collections.defaultdict(
        lambda: 'none',
        {
            Enum_Option.Pad1: 'pad',
            Enum_Option.PadN: 'pad',
            Enum_Option.Binding_Refresh_Advice: 'bra',
            Enum_Option.Alternate_Care_of_Address: 'aca',
            Enum_Option.Nonce_Indices: 'ni',
            Enum_Option.Authorization_Data: 'bad',
            Enum_Option.Mobile_Network_Prefix_Option: 'mnp',
            Enum_Option.Mobility_Header_Link_Layer_Address_option: 'lla',
            Enum_Option.MN_ID_OPTION_TYPE: 'mn_id',
            Enum_Option.AUTH_OPTION_TYPE: 'auth',
            Enum_Option.MESG_ID_OPTION_TYPE: 'mesg_id',
            Enum_Option.CGA_Parameters_Request: 'cga_pr',
            Enum_Option.CGA_Parameters: 'cga_param',
            Enum_Option.Signature: 'signature',
            Enum_Option.Permanent_Home_Keygen_Token: 'phkt',
            Enum_Option.Care_of_Test_Init: 'ct_init',
            Enum_Option.Care_of_Test: 'ct',
            Enum_Option.Experimental_Mobility_Option: 'exp',
            Enum_Option.Binding_Authorization_Data_for_FMIPv6: 'badf',
            Enum_Option.Mobility_Header_IPv6_Address_Prefix: 'ipv6_ap',
            Enum_Option.DNS_UPDATE_TYPE: 'dns',
            Enum_Option.Vendor_Specific_Mobility_Option: 'vendor',
            Enum_Option.Service_Selection_Mobility_Option: 'service',
            Enum_Option.Home_Network_Prefix_Option: 'hnp',
            Enum_Option.Handoff_Indicator_Option: 'hi',
            Enum_Option.Access_Technology_Type_Option: 'att',
            Enum_Option.Mobile_Node_Link_layer_Identifier_Option: 'mn_lli',
            Enum_Option.Link_local_Address_Option: 'lla_addr',
            Enum_Option.Timestamp_Option: 'timestamp',
            Enum_Option.Restart_Counter: 'restart',
            Enum_Option.IPv4_Home_Address: 'ipv4_hoa',
            Enum_Option.IPv4_Address_Acknowledgement: 'ipv4_ack',
            Enum_Option.NAT_Detection: 'nat',
            Enum_Option.IPv4_Care_of_Address: 'ipv4_coa',
            Enum_Option.GRE_Key_Option: 'gre',
            Enum_Option.Binding_Identifier: 'bid',
            Enum_Option.IPv4_Home_Address_Request: 'ipv4_hoa_req',
            Enum_Option.IPv4_Home_Address_Reply: 'ipv4_hoa_rep',
            Enum_Option.IPv4_Default_Router_Address: 'ipv4_router',
            Enum_Option.IPv4_DHCP_Support_Mode: 'ipv4_dhcp',
            Enum_Option.Context_Request_Option: 'cr',
            Enum_Option.Local_Mobility_Anchor_Address_Option: 'lmaa',
            Enum_Option.Mobile_Node_Link_local_Address_Interface_Identifier_Option: 'mn_lla_iid',
            Enum_Option.Transient_Binding: 'transient',
            Enum_Option.Flow_Summary_Mobility_Option: 'fs',
            Enum_Option.Flow_Identification_Mobility_Option: 'fid',
            Enum_Option.Redirect_Capability_Mobility_Option: 'rc',
            Enum_Option.Redirect_Mobility_Option: 'redirect',
            Enum_Option.Load_Information_Mobility_Option: 'load',
            Enum_Option.Alternate_IPv4_Care_of_Address: 'alt_ipv4_coa',
            Enum_Option.Mobile_Node_Group_Identifier: 'mn_group',
            Enum_Option.MAG_IPv6_Address: 'mag_addr',
            Enum_Option.Access_Network_Identifier: 'ani',
            Enum_Option.IPv4_Traffic_Offload_Selector: 'offload',
            Enum_Option.Dynamic_IP_Multicast_Selector: 'mcast_sel',
            Enum_Option.Delegated_Mobile_Network_Prefix: 'dmnp',
            Enum_Option.Active_Multicast_Subscription_IPv4: 'ams4',
            Enum_Option.Active_Multicast_Subscription_IPv6: 'ams6',
            Enum_Option.Quality_of_Service: 'qos',
            Enum_Option.LMA_User_Plane_Address: 'lma_up',
            Enum_Option.Multicast_Mobility_Option: 'mcast',
            Enum_Option.Multicast_Acknowledgement_Option: 'mcast_ack',
            Enum_Option.LMA_Controlled_MAG_Parameters: 'lcmp',
            Enum_Option.MAG_Multipath_Binding: 'mag_mp',
            Enum_Option.MAG_Identifier: 'mag_id',
            Enum_Option.Anchored_Prefix: 'anchored',
            Enum_Option.Local_Prefix: 'local_prefix',
            Enum_Option.Previous_MAAR: 'prev_maar',
            Enum_Option.Serving_MAAR: 'serv_maar',
            Enum_Option.DLIF_Link_Local_Address: 'dlif_lla',
            Enum_Option.DLIF_Link_Layer_Address: 'dlif_lladdr',
        },
    )  # type: DefaultDict[Enum_Option | int, str | tuple[OptionParser, OptionConstructor]]

    #: DefaultDict[Enum_CGAExtension, str | tuple[ExtensionParser, ExtensionConstructor]]:
    #: CGA extension type to method mapping. Method names are expected to be referred
    #: to the class by ``_read_extension_${name}`` and/or ``_make_ext_${name}``,
    #: and if such name not found, the value should then be a method that can
    #: parse the CGA extension by itself.
    __extension__ = collections.defaultdict(
        lambda: 'none',
        {
            Enum_CGAExtension.Multi_Prefix: 'multiprefix',
            Enum_CGAExtension.Exp_FFFD: 'exp',
            Enum_CGAExtension.Exp_FFFE: 'exp',
            Enum_CGAExtension.Exp_FFFF: 'exp',
        },
    )  # type: DefaultDict[Enum_CGAExtension | int, str | tuple[ExtensionParser, ExtensionConstructor]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Mobility Header"]':
        """Name of current protocol."""
        return 'Mobility Header'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.length

    @property
    def payload(self) -> 'Protocol | NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return super().payload

    @property
    def protocol(self) -> 'Optional[str] | NoReturn':
        """Name of next layer protocol (if any).

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protocol'")
        return super().protocol

    @property
    def protochain(self) -> 'ProtoChain | NoReturn':
        """Protocol chain of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protochain'")
        return super().protochain

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, *, version: 'Literal[4, 6]' = 4,  # pylint: disable=arguments-differ,unused-argument
             extension: bool = False, **kwargs: 'Any') -> 'Data_MH':  # pylint: disable=unused-argument
        """Read Mobility Header.

        Structure of MH header [:rfc:`6275`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Payload Proto |  Header Len   |   MH Type     |   Reserved    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Checksum            |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
           |                                                               |
           .                                                               .
           .                       Message Data                            .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            version: IP protocol version.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        name = self._lookup_registry(self.__message__, schema.type)
        if isinstance(name, str):
            meth_name = f'_read_msg_{name}'
            meth = cast('PacketParser',
                        getattr(self, meth_name, self._read_msg_unknown))
        else:
            meth = name[0]
        mh = meth(schema.data, header=schema)

        if extension:
            return mh
        return self._decode_next_layer(mh, schema.next, length - mh.length)

    def make(self,
             next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
             next_default: 'Optional[int]' = None,
             next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             next_reversed: 'bool' = False,
             type: 'Enum_Packet | StdlibEnum | AenumEnum | str | int' = Enum_Packet.Binding_Refresh_Request,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             chksum: 'bytes' = b'',
             data: 'bytes | Data_MH | Schema_Packet | dict[str, Any]' = b'\x00\x00',  # minimum length
             payload: 'Protocol | Schema | bytes' = b'',
             **kwargs: 'Any') -> 'Schema_MH':
        """Make (construct) packet data.

        Args:
            next: Next header type.
            next_default: Default value for next header type field.
            next_namespace: Namespace of next header type field.
            next_reversed: Whether the bits of next header type field is reversed.
            type: Mobility Header type.
            type_default: Default value for Mobility Header type field.
            type_namespace: Namespace of Mobility Header type field.
            type_reversed: Whether the bits of Mobility Header type field is reversed.
            chksum: Checksum.
            data: Message data.
            payload: Payload of next layer protocol.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        next_val = self._make_index(next, next_default, namespace=next_namespace,
                                    reversed=next_reversed, pack=False)
        type_val = self._make_index(type, type_default, namespace=type_namespace,
                                    reversed=type_reversed, pack=False)

        if isinstance(data, bytes):
            data_val = data  # type: bytes | Schema_Packet
        elif isinstance(data, (dict, Data_MH)):
            name = self._lookup_registry(self.__message__, type_val)
            if isinstance(name, str):
                meth_name = f'_make_msg_{name}'
                meth = cast('PacketConstructor',
                            getattr(self, meth_name, self._make_msg_unknown))
            else:
                meth = name[1]

            if isinstance(data, dict):
                data_val = meth(**data)
            else:
                data_val = meth(data)
        elif isinstance(data, Schema_Packet):
            data_val = data
        else:
            raise ProtocolError(f'MH: [Type {type_val}] invalid format')

        # NOTE: The header has to be a multiple of 8 octets, so the message data
        # needs padding until ``len(data) + 6`` is aligned. Rounding ``length`` up
        # without emitting that padding -- which is what ``math.ceil`` used to do
        # here -- declares a header longer than the bytes that follow it, and the
        # re-parse then reads whatever happens to be past the end of the buffer.
        data_val = self._pad_mh_message(data_val)

        return Schema_MH(
            next=next_val,
            length=(len(data_val) + 6) // 8 - 1,
            type=type_val,
            chksum=chksum,
            data=data_val,
            payload=payload,
        )

    @classmethod
    def register_message(cls, code: 'Enum_Packet', meth: 'str | tuple[PacketParser, PacketConstructor]') -> 'None':
        """Register a message parser.

        Args:
            code: MH message type code.
            meth: Method name or callable to parse and/or construct the message.

        """
        if code in cls.__message__:
            warn(f'message type {code} already registered, overwriting', RegistryWarning)
        cls.__message__[code] = meth

    @classmethod
    def register_option(cls, code: 'Enum_Option', meth: 'str | tuple[OptionParser, OptionConstructor]') -> 'None':
        """Register an option parser.

        Args:
            code: MH option code.
            meth: Method name or callable to parse and/or construct the option.

        """
        if code in cls.__option__:
            warn(f'option {code} already registered, overwriting', RegistryWarning)
        cls.__option__[code] = meth

    @classmethod
    def register_extension(cls, code: 'Enum_CGAExtension', meth: 'str | tuple[ExtensionParser, ExtensionConstructor]') -> 'None':
        """Register a CGA extension parser.

        Args:
            code: CGA extension code.
            meth: Method name or callable to parse and/or construct the extension.

        """
        if code in cls.__extension__:
            warn(f'extension {code} already registered, overwriting', RegistryWarning)
        cls.__extension__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      extension: 'bool' = ..., **kwargs: 'Any') -> 'None': ...

    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      extension: 'bool' = False, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`self.make <MH.make>`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, extension=extension, **kwargs)  # type: ignore[arg-type]

    def __length_hint__(self) -> 'Literal[6]':
        """Return an estimated length for the object."""
        return 6

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.Mobility_Header  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_MH') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'next': data.next,
            'type': data.type,
            'chksum': data.chksum,
            'data': data,
            'payload': cls._make_payload(data),
        }

    def _read_msg_unknown(self, schema: 'Schema_UnknownMessage', *,
                          header: 'Schema_MH') -> 'Data_UnknownMessage':
        """Read unknown MH message type.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_UnknownMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            data=schema.data,
        )
        return data

    def _read_msg_brr(self, schema: 'Schema_BindingRefreshRequestMessage', *,
                      header: 'Schema_MH') -> 'Data_BindingRefreshRequestMessage':
        """Read MH binding refresh request (BRR) message type.

        Structure of MH Binding Refresh Request Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |          Reserved             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_BindingRefreshRequestMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            options=self._read_mh_options(schema.options)
        )
        return data

    def _read_msg_hoti(self, schema: 'Schema_HomeTestInitMessage', *,
                       header: 'Schema_MH') -> 'Data_HomeTestInitMessage':
        """Read MH home test initiation (HoTI) message type.

        Structure of MH Home Test Initiation Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                       Home Init Cookie                        +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                       Mobility Options                        .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_HomeTestInitMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            cookie=schema.cookie,
            options=self._read_mh_options(schema.options)
        )
        return data

    def _read_msg_coti(self, schema: 'Schema_CareofTestInitMessage', *,
                       header: 'Schema_MH') -> 'Data_CareofTestInitMessage':
        """Read MH care-of test initiation (CoTI) message type.

        Structure of MH Care-of Test Initiation Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                      Care-of Init Cookie                      +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_CareofTestInitMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            cookie=schema.cookie,
            options=self._read_mh_options(schema.options)
        )
        return data

    def _read_msg_hot(self, schema: 'Schema_HomeTestMessage', *,
                      header: 'Schema_MH') -> 'Data_HomeTestMessage':
        """Read MH home test (HoT) message type.

        Structure of MH Home Test Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |       Home Nonce Index        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                        Home Init Cookie                       +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                       Home Keygen Token                       +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_HomeTestMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            nonce_index=schema.nonce_index,
            cookie=schema.cookie,
            token=schema.token,
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_cot(self, schema: 'Schema_CareofTestMessage', *,
                      header: 'Schema_MH') -> 'Data_CareofTestMessage':
        """Read MH care-of test (CoT) message type.

        Structure of MH Care-of Test Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |      Care-of Nonce Index      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                      Care-of Init Cookie                      +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                     Care-of Keygen Token                      +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_CareofTestMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            nonce_index=schema.nonce_index,
            cookie=schema.cookie,
            token=schema.token,
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_bu(self, schema: 'Schema_BindingUpdateMessage', *,
                     header: 'Schema_MH') -> 'Data_BindingUpdateMessage':
        """Read MH binding update (BU) message type.

        Structure of MH Binding Update Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |          Sequence #           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |A|H|L|K|        Reserved       |           Lifetime            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_BindingUpdateMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            seq=schema.seq,
            ack=bool(schema.flags['A']),
            home=bool(schema.flags['H']),
            lla_compat=bool(schema.flags['L']),
            key_mngt=bool(schema.flags['K']),
            lifetime=datetime.timedelta(seconds=schema.lifetime * 4),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_ba(self, schema: 'Schema_BindingAcknowledgementMessage', *,
                     header: 'Schema_MH') -> 'Data_BindingAcknowledgementMessage':
        """Read MH binding acknowledgement (BA) message type.

        Structure of MH Binding Acknowledgement Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |    Status     |K|  Reserved   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Sequence #          |           Lifetime            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_BindingAcknowledgementMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            status=schema.status,
            key_mngt=bool(schema.flags['K']),
            seq=schema.seq,
            lifetime=datetime.timedelta(seconds=schema.lifetime * 4),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_be(self, schema: 'Schema_BindingErrorMessage', *,
                     header: 'Schema_MH') -> 'Data_BindingErrorMessage':
        """Read MH binding error (BE) message type.

        Structure of MH Binding Error Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |     Status    |   Reserved    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                          Home Address                         +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_BindingErrorMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            status=schema.status,
            home=schema.home,
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_fbu(self, schema: 'Schema_FastBindingUpdateMessage', *,
                      header: 'Schema_MH') -> 'Data_FastBindingUpdateMessage':
        """Read MH fast binding update (FBU) message type.

        Structure of MH Fast Binding Update Message [:rfc:`5568#section-6.2.2`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |          Sequence #           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |A|H|L|K|       Reserved        |            Lifetime           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            :rfc:`5568#section-6.2.2` states that the FBU is *identical* to the
            Mobile IPv6 binding update (BU) message, so the lifetime is read in
            units of 4 seconds exactly as in :meth:`_read_msg_bu`.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_FastBindingUpdateMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            seq=schema.seq,
            ack=bool(schema.flags['A']),
            home=bool(schema.flags['H']),
            lla_compat=bool(schema.flags['L']),
            key_mngt=bool(schema.flags['K']),
            lifetime=datetime.timedelta(seconds=schema.lifetime * 4),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_fback(self, schema: 'Schema_FastBindingAcknowledgmentMessage', *,
                        header: 'Schema_MH') -> 'Data_FastBindingAcknowledgmentMessage':
        """Read MH fast binding acknowledgment (FBack) message type.

        Structure of MH Fast Binding Acknowledgment Message [:rfc:`5568#section-6.2.3`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |     Status    |K|  Reserved   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |            Sequence #         |            Lifetime           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            :rfc:`5568#section-6.2.3` defines the FBack status values inline
            instead of drawing them from the IANA *Status Codes* registry, whose
            values ``1`` and ``131`` mean something else entirely. The status is
            therefore reported as a
            :class:`~pcapkit.protocols.internet.mh.FastBindingAcknowledgmentStatus`,
            which is local to this module, rather than being mislabelled as a
            :class:`~pcapkit.const.mh.status_code.StatusCode`.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_FastBindingAcknowledgmentMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            status=FastBindingAcknowledgmentStatus(schema.status),
            key_mngt=bool(schema.flags['K']),
            seq=schema.seq,
            lifetime=datetime.timedelta(seconds=schema.lifetime * 4),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_fna(self, schema: 'Schema_FastNeighborAdvertisementMessage', *,
                      header: 'Schema_MH') -> 'Data_FastNeighborAdvertisementMessage':
        """Read MH fast neighbor advertisement (FNA) message type.

        Structure of MH Fast Neighbor Advertisement Message [:rfc:`4068#section-6.3.3`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The FNA message is **deprecated** by :rfc:`5568#section-8`, which
            replaces it with the unsolicited neighbor advertisement (UNA) of
            :rfc:`4861`. Its wire format is therefore taken from :rfc:`4068`,
            the specification :rfc:`5568` obsoletes, since a NAR is still
            permitted to process the message as specified there.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_FastNeighborAdvertisementMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_emh(self, schema: 'Schema_ExperimentalMessage', *,
                      header: 'Schema_MH') -> 'Data_ExperimentalMessage':
        """Read MH experimental mobility header message type.

        Structure of MH Experimental Mobility Header Message [:rfc:`5096#section-3`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Payload Proto |  Header Len   |   MH Type     |   Reserved    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Checksum            |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
           |                                                               |
           .                                                               .
           .                       Message Data                            .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            :rfc:`5096#section-3` defines no fields beyond those of the mobility
            header itself, so the message data is carried opaquely -- its layout
            is whatever the experiment in question defines. Two bytes of padding
            are required when no data is present.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_ExperimentalMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            data=schema.data,
        )
        return data

    def _read_msg_hi(self, schema: 'Schema_HandoverInitiateMessage', *,
                     header: 'Schema_MH') -> 'Data_HandoverInitiateMessage':
        """Read MH handover initiate (HI) message type.

        Structure of MH Handover Initiate Message [:rfc:`5568#section-6.2.1.1`,
        :rfc:`5949#section-6.1.1`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |          Sequence #           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |S|U|P|F| Resv  |      Code     |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               .
           |                                                               |
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            :rfc:`5568` defines only the ``S`` and ``U`` flags; the ``P`` and
            ``F`` flags, and code values ``2`` and ``3``, are added by
            :rfc:`5949#section-6.1.1`. All four flags are registered in the IANA
            *Handover Initiate Flags* registry, hence all four are parsed here.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_HandoverInitiateMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            seq=schema.seq,
            assign=bool(schema.flags['S']),
            buffer=bool(schema.flags['U']),
            proxy=bool(schema.flags['P']),
            forward=bool(schema.flags['F']),
            code=schema.code,
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_hack(self, schema: 'Schema_HandoverAcknowledgeMessage', *,
                       header: 'Schema_MH') -> 'Data_HandoverAcknowledgeMessage':
        """Read MH handover acknowledge (HAck) message type.

        Structure of MH Handover Acknowledge Message [:rfc:`5568#section-6.2.1.2`,
        :rfc:`5949#section-6.1.2`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |          Sequence #           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |U|P|F| Reserved|      Code     |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               .
           |                                                               |
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            :rfc:`5568` reserves the whole first octet of the message data; the
            ``U``, ``P`` and ``F`` flags carved out of it, and code values ``5``
            and ``6``, are added by :rfc:`5949#section-6.1.2`. All three flags
            are registered in the IANA *Handover Acknowledge Flags* registry,
            hence all three are parsed here.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_HandoverAcknowledgeMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            seq=schema.seq,
            buffer=bool(schema.flags['U']),
            proxy=bool(schema.flags['P']),
            forward=bool(schema.flags['F']),
            code=schema.code,
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_has(self, schema: 'Schema_HomeAgentSwitchMessage', *,
                      header: 'Schema_MH') -> 'Data_HomeAgentSwitchMessage':
        """Read MH home agent switch (HAS) message type.

        Structure of MH Home Agent Switch Message [:rfc:`5142#section-4`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |# of Addresses |   Reserved    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           .                                                               .
           .                      Home Agent Addresses                     .
           .                                                               .
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The ``# of Addresses`` field is not carried into the data model,
            since it is exactly ``len(addresses)`` and a second copy of a length
            is a second thing to keep in step. An empty list is meaningful rather
            than degenerate: :rfc:`5142#section-4` uses a count of zero to tell
            the mobile node to run home agent discovery instead.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        if schema.count != len(schema.addresses):
            raise ProtocolError(f'{self.alias}: [Type {header.type}] invalid format')

        data = Data_HomeAgentSwitchMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            addresses=tuple(schema.addresses),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_hb(self, schema: 'Schema_HeartbeatMessage', *,
                     header: 'Schema_MH') -> 'Data_HeartbeatMessage':
        """Read MH heartbeat message type.

        Structure of MH Heartbeat Message [:rfc:`5847#section-3.3`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |            Reserved       |U|R|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                       Sequence Number                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The ``U`` and ``R`` flags are the two **least** significant bits of
            the first half-word, not the most significant ones the other mobility
            messages put their flags in [:rfc:`5847#section-3.3`]. The sequence
            number is 32 bits wide, also unlike the 16-bit ones elsewhere.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_HeartbeatMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            unsolicited=bool(schema.flags['U']),
            response=bool(schema.flags['R']),
            seq=schema.seq,
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_brm(self, schema: 'Schema_BindingRevocationMessage', *,
                      header: 'Schema_MH') -> 'Data_BindingRevocationMessage':
        """Read MH binding revocation (BRM) message type.

        Structure of MH Binding Revocation Indication Message
        [:rfc:`5846#section-5.1`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           | B.R. Type = 1 |  R. Trigger   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Sequence #           |P|V|G|       Reserved          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility options                       .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Structure of MH Binding Revocation Acknowledgement Message
        [:rfc:`5846#section-5.2`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           | B.R. Type = 2 |    Status     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |            Sequence #         |P|V|G|       Reserved          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            One Mobility Header type carries both forms, told apart by the
            ``B.R. Type`` octet **inside** the message rather than by the header
            type. The two have identical geometry, and the only field whose
            meaning differs is the octet after it -- a revocation trigger in an
            indication and a status code in an acknowledgement, drawn from two
            different registries -- so a single data model carries both, with
            :attr:`~pcapkit.protocols.data.internet.mh.BindingRevocationMessage.br_type`
            saying which it is.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_BindingRevocationMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            br_type=schema.br_type,
            code=schema.code,
            seq=schema.seq,
            proxy=bool(schema.flags['P']),
            ipv4_hoa=bool(schema.flags['V']),
            global_revocation=bool(schema.flags['G']),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_lri(self, schema: 'Schema_LocalizedRoutingInitiationMessage', *,
                      header: 'Schema_MH') -> 'Data_LocalizedRoutingInitiationMessage':
        """Read MH localized routing initiation (LRI) message type.

        Structure of MH Localized Routing Initiation Message
        [:rfc:`6705#section-10.1`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |           Sequence #          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Reserved              |           Lifetime            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The lifetime is in **seconds** here, not in the units of 4 seconds
            that :rfc:`6275` uses for the binding messages
            [:rfc:`6705#section-10.1`], so it is not scaled on the way in.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_LocalizedRoutingInitiationMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            seq=schema.seq,
            lifetime=datetime.timedelta(seconds=schema.lifetime),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_lra(self, schema: 'Schema_LocalizedRoutingAcknowledgmentMessage', *,
                      header: 'Schema_MH') -> 'Data_LocalizedRoutingAcknowledgmentMessage':
        """Read MH localized routing acknowledgment (LRA) message type.

        Structure of MH Localized Routing Acknowledgment Message
        [:rfc:`6705#section-10.2`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |           Sequence #          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |U|  Reserved   |   Status      |           Lifetime            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        The status codes are enumerated in
        :class:`~pcapkit.protocols.internet.mh.LocalizedRoutingStatus`, which is
        local to this module because :rfc:`6705` defines them inline and IANA
        registers them nowhere -- not even in the general *Status Codes*
        registry.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_LocalizedRoutingAcknowledgmentMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            seq=schema.seq,
            unsolicited=bool(schema.flags['U']),
            status=LocalizedRoutingStatus(schema.status),
            lifetime=datetime.timedelta(seconds=schema.lifetime),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_upn(self, schema: 'Schema_UpdateNotificationMessage', *,
                      header: 'Schema_MH') -> 'Data_UpdateNotificationMessage':
        """Read MH update notification (UPN) message type.

        Structure of MH Update Notification Message [:rfc:`7077#section-4.1`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |           Sequence #          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |    Notification Reason        |A|D|          Reserved         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The notification reason is **16** bits wide, not the 8 that a status
            octet elsewhere in the Mobility Header would be.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_UpdateNotificationMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            seq=schema.seq,
            reason=schema.reason,
            ack=bool(schema.flags['A']),
            retransmit=bool(schema.flags['D']),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_upa(self, schema: 'Schema_UpdateNotificationAcknowledgementMessage', *,
                      header: 'Schema_MH') -> 'Data_UpdateNotificationAcknowledgementMessage':
        """Read MH update notification acknowledgement (UPA) message type.

        Structure of MH Update Notification Acknowledgement Message
        [:rfc:`7077#section-4.2`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |           Sequence #          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Status Code |                   Reserved                    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_UpdateNotificationAcknowledgementMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            seq=schema.seq,
            status=schema.status,
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_fbm(self, schema: 'Schema_FlowBindingMessage', *,
                      header: 'Schema_MH') -> 'Data_FlowBindingMessage':
        """Read MH flow binding (FB) message type.

        Structure of MH Flow Binding Indication Message
        [:rfc:`7109#section-6.1.1`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |      Flow Binding Type = 1    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Sequence #           |   Trigger     |A|  Reserved   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility options                       .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Structure of MH Flow Binding Acknowledgement Message
        [:rfc:`7109#section-6.1.2`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |       Flow Binding Type = 2   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Sequence #           |   Status      |    Reserved   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility options                       .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            As with the binding revocation message, one Mobility Header type
            carries both forms and the ``Flow Binding Type`` field inside the
            message says which. The ``A`` flag exists only in the indication; the
            acknowledgement reserves the whole octet it is taken from, so a
            well-formed acknowledgement reads back as ``ack=False``.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_FlowBindingMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            fb_type=schema.fb_type,
            seq=schema.seq,
            code=schema.code,
            ack=bool(schema.flags['A']),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_sq(self, schema: 'Schema_SubscriptionQueryMessage', *,
                     header: 'Schema_MH') -> 'Data_SubscriptionQueryMessage':
        """Read MH subscription query (SQ) message type.

        Structure of MH Subscription Query Message [:rfc:`7161#section-4.3.1.2`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Sequence #   |   Reserved    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The sequence number is a single octet, counted modulo 256, unlike the
            16-bit ones of most other mobility messages
            [:rfc:`7161#section-4.3.1.2`].

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_SubscriptionQueryMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            seq=schema.seq,
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_sr(self, schema: 'Schema_SubscriptionResponseMessage', *,
                     header: 'Schema_MH') -> 'Data_SubscriptionResponseMessage':
        """Read MH subscription response (SR) message type.

        Structure of MH Subscription Response Message
        [:rfc:`7161#section-4.3.2.2`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Sequence #   |I|  Reserved   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_SubscriptionResponseMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            seq=schema.seq,
            info=bool(schema.flags['I']),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_mh_options(self, options_schema: 'list[Schema_Option]') -> 'Option':
        """Read MH options.

        Structure of MH option [:rfc:`6275`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Option Type  | Option Length |   Option Data...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            options_schema: Parsed MH options.

        Returns:
            Parsed MH options data.

        """
        options = OrderedMultiDict()  # type: Option

        for schema in options_schema:
            type = schema.type
            name = self._lookup_registry(self.__option__, type)

            if isinstance(name, str):
                meth_name = f'_read_opt_{name}'
                meth = cast('OptionParser',
                            getattr(self, meth_name, self._read_opt_none))
            else:
                meth = name[0]
            data = meth(schema, options=options)

            # record option data
            options.add(type, data)

        return options

    def _read_opt_none(self, schema: 'Schema_UnassignedOption', *,
                             options: 'Option') -> 'Data_UnassignedOption':
        """Read MH unassigned option.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        data = Data_UnassignedOption(
            type=schema.type,
            length=schema.length + 2,
            data=schema.data,
        )
        return data

    def _read_opt_pad(self, schema: 'Schema_PadOption', *,
                      options: 'Option') -> 'Data_PadOption':
        """Read MH padding option.

        Structure of MH padding option [:rfc:`6275`]:

        * ``Pad1`` option:

          .. code-block:: text

              0
              0 1 2 3 4 5 6 7
             +-+-+-+-+-+-+-+-+
             |   Type = 0    |
             +-+-+-+-+-+-+-+-+

        * ``PadN`` option:

          .. code-block:: text

              0                   1
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
             |   Type = 1    | Option Length | Option Data
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        code, clen = schema.type, schema.length

        if code not in (Enum_Option.Pad1, Enum_Option.PadN):
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        if code == Enum_Option.Pad1 and clen != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        if code == Enum_Option.PadN and clen == 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        if code == Enum_Option.Pad1:
            size = 1
        else:
            size = clen + 2

        data = Data_PadOption(
            type=schema.type,
            length=size,
        )
        return data

    def _read_opt_bra(self, schema: 'Schema_BindingRefreshAdviceOption', *,
                      options: 'Option') -> 'Data_BindingRefreshAdviceOption':
        """Read MH binding refresh advice option.

        Structure of MH Binding Refresh Advice option [:rfc:`6275`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |   Type = 2    |   Length = 2  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |       Refresh Interval        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 2:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_BindingRefreshAdviceOption(
            type=schema.type,
            length=schema.length + 2,
            interval=schema.interval,
        )
        return data

    def _read_opt_aca(self, schema: 'Schema_AlternateCareofAddressOption', *,
                      options: 'Option') -> 'Data_AlternateCareofAddressOption':
        """Read MH alternate care-of address option.

        Structure of MH Alternate Care-of Address option [:rfc:`6275`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |   Type = 3    |  Length = 16  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                   Alternate Care-of Address                   +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 16:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_AlternateCareofAddressOption(
            type=schema.type,
            length=schema.length + 2,
            address=schema.address,
        )
        return data

    def _read_opt_ni(self, schema: 'Schema_NonceIndicesOption', *,
                     options: 'Option') -> 'Data_NonceIndicesOption':
        """Read MH nonce indices option.

        Structure of MH Nonce Indices option [:rfc:`6275`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |   Type = 4    |   Length = 4  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Home Nonce Index      |     Care-of Nonce Index       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_NonceIndicesOption(
            type=schema.type,
            length=schema.length + 2,
            home=schema.home,
            careof=schema.careof,
        )
        return data

    def _read_opt_bad(self, schema: 'Schema_AuthorizationDataOption', *,
                      options: 'Option') -> 'Data_AuthorizationDataOption':
        """Read MH binding authorization data option.

        Structure of MH Binding Authorization Data option [:rfc:`6275`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |   Type = 5    | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                         Authenticator                         |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length % 8 != 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_AuthorizationDataOption(
            type=schema.type,
            length=schema.length + 2,
            data=schema.data,
        )
        return data

    def _read_opt_mnp(self, schema: 'Schema_MobileNetworkPrefixOption', *,
                      options: 'Option') -> 'Data_MobileNetworkPrefixOption':
        """Read MH mobile network prefix option.

        Structure of MH Mobile Network Prefix option [:rfc:`3963`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |   Reserved    | Prefix Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                   Mobile Network Prefix                       +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 18:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        prefix = cast('IPv6Network',
                      ipaddress.ip_network((schema.prefix, schema.prefix_length)))

        data = Data_MobileNetworkPrefixOption(
            type=schema.type,
            length=schema.length + 2,
            prefix=prefix,
        )
        return data

    def _read_opt_lla(self, schema: 'Schema_LinkLayerAddressOption', *,
                      options: 'Option') -> 'Data_LinkLayerAddressOption':
        """Read MH link-layer address (MH-LLA) option.

        Structure of MH Link-Layer Address option [:rfc:`5568`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                         |     Type      |     Length    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Option-Code   |                  LLA                     ....
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.code != Enum_LLACode.MH:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_LinkLayerAddressOption(
            type=schema.type,
            length=schema.length + 2,
            code=schema.code,
            lla=schema.lla,
        )
        return data

    def _read_opt_mn_id(self, schema: 'Schema_MNIDOption', *,
                       options: 'Option') -> 'Data_MNIDOption':
        """Read MH mobile node identifier option.

        Structure of MH Mobile Node Identifier option [:rfc:`4283`]:

        .. code-block:: text

           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Subtype      |          Identifier ...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        data = Data_MNIDOption(
            type=schema.type,
            length=schema.length + 2,
            subtype=schema.subtype,
            identifier=schema.identifier,
        )
        return data

    def _read_opt_auth(self, schema: 'Schema_AuthOption', *,
                       options: 'Option') -> 'Data_AuthOption':
        """Read MH mobility message authentication option.

        Structure of MH Mobility Message Authentication option [:rfc:`4285`]:

        .. code-block:: text

           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                           |  Option Type  | Option Length |  Subtype      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  Mobility SPI                                 |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  Authentication Data ....
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if (schema.length + 1) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_AuthOption(
            type=schema.type,
            length=schema.length + 2,
            subtype=schema.subtype,
            spi=schema.spi,
            data=schema.data,
        )
        return data

    def _read_opt_mesg_id(self, schema: 'Schema_MesgIDOption', *,
                          options: 'Option') -> 'Data_MesgIDOption':
        """Read MH mobility message replay protection option.

        Structure of MH Mobility Message Replay Protection option [:rfc:`4285`]:

        .. code-block:: text

           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                       |      Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  Timestamp ...                                |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  Timestamp                                    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if (schema.length) % 8 != 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_MesgIDOption(
            type=schema.type,
            length=schema.length + 2,
            timestamp=schema.timestamp,
            ntp_timestamp=NTPTimestamp(schema.seconds, schema.fraction),
        )
        return data

    def _read_opt_cga_pr(self, schema: 'Schema_CGAParametersRequestOption', *,
                         options: 'Option') -> 'Data_CGAParametersRequestOption':
        """Read MH CGA parameters request option.

        Structure of MH CGA Parameters Request option [:rfc:`4866`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_CGAParametersRequestOption(
            type=schema.type,
            length=schema.length + 2,
        )
        return data

    def _read_opt_cga_param(self, schema: 'Schema_CGAParametersOption', *,
                            options: 'Option') -> 'Data_CGAParametersOption':
        """Read MH CGA parameters option.

        Structure of MH CGA Parameters option [:rfc:`4866`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           :                                                               :
           :                          CGA Parameters                       :
           :                                                               :
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        for param in schema.parameters:
            if param.collision_count not in (0, 1, 2):
                raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_CGAParametersOption(
            type=schema.type,
            length=schema.length + 2,
            parameters=tuple(Data_CGAParameter(
                modifier=param.modifier,
                prefix=param.prefix,
                collision_count=param.collision_count,
                public_key=param.public_key,
                extensions=self._read_cga_extensions(param.extensions),
            ) for param in schema.parameters),
        )
        return data

    def _read_opt_signature(self, schema: 'Schema_SignatureOption', *,
                            options: 'Option') -> 'Data_SignatureOption':
        """Read MH signature option.

        Structure of MH Signature option [:rfc:`4866`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           :                                                               :
           :                            Signature                          :
           :                                                               :
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        data = Data_SignatureOption(
            type=schema.type,
            length=schema.length + 2,
            signature=schema.signature,
        )
        return data

    def _read_opt_phkt(self, schema: 'Schema_PermanentHomeKeygenTokenOption', *,
                       options: 'Option') -> 'Data_PermanentHomeKeygenTokenOption':
        """Read MH permanent home keygen token option.

        Structure of MH Permanent Home Keygen Token option [:rfc:`4866`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           :                                                               :
           :                  Permanent Home Keygen Token                  :
           :                                                               :
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        data = Data_PermanentHomeKeygenTokenOption(
            type=schema.type,
            length=schema.length + 2,
            token=schema.token,
        )
        return data

    def _read_opt_ct_init(self, schema: 'Schema_CareofTestInitOption', *,
                          options: 'Option') -> 'Data_CareofTestInitOption':
        """Read MH Care-of Test Init option.

        Structure of MH Care-of Test Init option [:rfc:`4866`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_CareofTestInitOption(
            type=schema.type,
            length=schema.length + 2,
        )
        return data

    def _read_opt_ct(self, schema: 'Schema_CareofTestOption', *,
                     options: 'Option') -> 'Data_CareofTestOption':
        """Read MH Care-of Test option.

        Structure of MH Care-of Test option [:rfc:`4866`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                     Care-of Keygen Token                      +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 8:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_CareofTestOption(
            type=schema.type,
            length=schema.length + 2,
            token=schema.token,
        )
        return data

    def _read_opt_exp(self, schema: 'Schema_ExperimentalMobilityOption', *,
                      options: 'Option') -> 'Data_ExperimentalMobilityOption':
        """Read MH experimental mobility option.

        Structure of MH Experimental Mobility option [:rfc:`5096#section-4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |        Data .....
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        data = Data_ExperimentalMobilityOption(
            type=schema.type,
            length=schema.length + 2,
            data=schema.data,
        )
        return data

    def _read_opt_badf(self, schema: 'Schema_BADFOption', *,
                       options: 'Option') -> 'Data_BADFOption':
        """Read MH binding authorization data for FMIPv6 (BADF) option.

        Structure of MH Binding Authorization Data for FMIPv6 option
        [:rfc:`5568#section-6.4.5`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |   Type = 21   | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                              SPI                              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                         Authenticator                         |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            :rfc:`5568#section-6.4.5` defines the option length as *the length of
            the Authenticator in bytes*, i.e. it does **not** cover the 4-byte
            SPI, unlike every other mobility option, whose length covers all of
            its option data. The wording is inherited from the :rfc:`6275`
            binding authorization data option (type ``5``), which carries no SPI
            and for which the two readings coincide. Because :rfc:`5568` also
            requires this option to be the **last** mobility option present, the
            discrepancy never has to be resolved in order to find the following
            option, so the literal reading is used here and the reported
            :attr:`~pcapkit.protocols.data.internet.mh.Option.length` accounts
            for the extra 4 bytes.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length == 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_BADFOption(
            type=schema.type,
            length=schema.length + 6,  # 2 bytes for type & length, 4 bytes for SPI
            spi=schema.spi,
            data=schema.data,
        )
        return data

    def _read_opt_ipv6_ap(self, schema: 'Schema_IPv6AddressPrefixOption', *,
                          options: 'Option') -> 'Data_IPv6AddressPrefixOption':
        """Read MH mobility header IPv6 address/prefix option.

        Structure of MH Mobility Header IPv6 Address/Prefix option
        [:rfc:`5568#section-6.4.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |  Option-Code  | Prefix Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                     IPv6 Address/Prefix                       +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        The option code identifies which address the option carries, c.f.,
        :class:`~pcapkit.protocols.internet.mh.IPv6AddressPrefixCode`. It, too,
        is defined inline by :rfc:`5568#section-6.4.2` with no IANA registry
        behind it, hence the enumeration is local to this module.

        Note:
            :rfc:`5568` prints the type as ``17``, which is the *neighbor
            discovery* option type of its sibling in
            :rfc:`5568#section-6.4.1`. Errata ID 1816 (verified) corrects it to
            the IANA-assigned mobility option type ``34``, which is what this
            handler is registered against.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 18:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')
        if schema.prefix_length > 128:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_IPv6AddressPrefixOption(
            type=schema.type,
            length=schema.length + 2,
            code=IPv6AddressPrefixCode(schema.code),
            prefix_length=schema.prefix_length,
            address=schema.address,
        )
        return data

    def _read_opt_dns(self, schema: 'Schema_DNSUpdateOption', *,
                      options: 'Option') -> 'Data_DNSUpdateOption':
        """Read MH DNS-UPDATE-TYPE option.

        Structure of MH DNS-UPDATE-TYPE option [:rfc:`5026#section-8.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Status      |R|  Reserved   |     MN identity (FQDN) ...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The status field draws from the *Status Codes (DNS Update Mobility
            Option)* registry that :rfc:`5026#section-10` creates, **not** from
            the general mobility status codes, which is why it is typed
            :class:`~pcapkit.const.mh.dns_status_code.DNSStatusCode`.

            The identity is kept as :obj:`bytes` rather than decoded to
            :class:`str`, because the RFC says only "FQDN format" without saying
            whether that means the presentation form or the length-prefixed
            label form of :rfc:`1035`.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length < 2:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_DNSUpdateOption(
            type=schema.type,
            length=schema.length + 2,
            status=schema.status,
            remove=bool(schema.flags['R']),
            identity=schema.identity,
        )
        return data

    def _read_opt_vendor(self, schema: 'Schema_VendorSpecificOption', *,
                         options: 'Option') -> 'Data_VendorSpecificOption':
        """Read MH vendor specific mobility option.

        Structure of MH Vendor Specific mobility option [:rfc:`5094#section-3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |     Type      |   Length      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Vendor ID                             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Sub-Type    |             Data.......
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The vendor ID is an SMI Network Management Private Enterprise Number,
            whose space is unbounded, so it is not enumerated. The sub-type is
            administered by that vendor rather than by IANA, so it is not
            enumerated either.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length < 5:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_VendorSpecificOption(
            type=schema.type,
            length=schema.length + 2,
            vendor=schema.vendor,
            subtype=schema.subtype,
            data=schema.data,
        )
        return data

    def _read_opt_service(self, schema: 'Schema_ServiceSelectionOption', *,
                          options: 'Option') -> 'Data_ServiceSelectionOption':
        """Read MH service selection mobility option.

        Structure of MH Service Selection mobility option [:rfc:`5149#section-3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Type = 20    |   Length      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Identifier...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            Unlike the DNS identity of :meth:`_read_opt_dns`, this identifier is
            decoded to :class:`str`: :rfc:`5149#section-3` states outright that it
            is UTF-8 and NFKC-normalised. A length of zero is invalid.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length == 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_ServiceSelectionOption(
            type=schema.type,
            length=schema.length + 2,
            identifier=schema.identifier,
        )
        return data

    def _read_opt_hnp(self, schema: 'Schema_HomeNetworkPrefixOption', *,
                      options: 'Option') -> 'Data_HomeNetworkPrefixOption':
        """Read MH home network prefix option.

        Structure of MH Home Network Prefix option [:rfc:`5213#section-8.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |   Reserved    | Prefix Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                    Home Network Prefix                        +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 18:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')
        if schema.prefix_length > 128:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_HomeNetworkPrefixOption(
            type=schema.type,
            length=schema.length + 2,
            prefix_length=schema.prefix_length,
            prefix=schema.prefix,
        )
        return data

    def _read_opt_hi(self, schema: 'Schema_HandoffIndicatorOption', *,
                     options: 'Option') -> 'Data_HandoffIndicatorOption':
        """Read MH handoff indicator option.

        Structure of MH Handoff Indicator option [:rfc:`5213#section-8.4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |  Reserved (R) |       HI      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 2:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_HandoffIndicatorOption(
            type=schema.type,
            length=schema.length + 2,
            hi=schema.hi,
        )
        return data

    def _read_opt_att(self, schema: 'Schema_AccessTechnologyTypeOption', *,
                      options: 'Option') -> 'Data_AccessTechnologyTypeOption':
        """Read MH access technology type option.

        Structure of MH Access Technology Type option [:rfc:`5213#section-8.5`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |  Reserved (R) |      ATT      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            :rfc:`5213` itself defines only access types ``0`` through ``5``.
            Values ``6`` through ``13`` were registered directly with IANA against
            3GPP and 3GPP2 specifications rather than through an updating RFC, and
            :class:`~pcapkit.const.mh.access_type.AccessType` carries all of them.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 2:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_AccessTechnologyTypeOption(
            type=schema.type,
            length=schema.length + 2,
            att=schema.att,
        )
        return data

    def _read_opt_mn_lli(self, schema: 'Schema_MNLLIdentifierOption', *,
                         options: 'Option') -> 'Data_MNLLIdentifierOption':
        """Read MH mobile node link-layer identifier option.

        Structure of MH Mobile Node Link-layer Identifier option
        [:rfc:`5213#section-8.6`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type        |    Length     |          Reserved             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                        Link-layer Identifier                  +
           .                              ...                              .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The identifier's octet and bit ordering is that of
            :rfc:`4861#section-4.6`, but only the *address encoding* is borrowed
            from there -- the option keeps its own mobility-option framing, in
            which the length is in octets rather than in the 8-octet units
            neighbour discovery uses.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length < 2:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_MNLLIdentifierOption(
            type=schema.type,
            length=schema.length + 2,
            lli=schema.lli,
        )
        return data

    def _read_opt_lla_addr(self, schema: 'Schema_LinkLocalAddressOption', *,
                           options: 'Option') -> 'Data_LinkLocalAddressOption':
        """Read MH link-local address option.

        Structure of MH Link-local Address option [:rfc:`5213#section-8.7`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |   Type        |    Length     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                  Link-local Address                           +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            :rfc:`6543` reserves ``0200:5EFF:FE00:5213`` as the interface
            identifier a mobile access gateway may use here when it does not vary
            the address per access link. That changes which values are expected,
            not the option's shape.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 16:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_LinkLocalAddressOption(
            type=schema.type,
            length=schema.length + 2,
            address=schema.address,
        )
        return data

    def _read_opt_timestamp(self, schema: 'Schema_TimestampOption', *,
                            options: 'Option') -> 'Data_TimestampOption':
        """Read MH timestamp option.

        Structure of MH Timestamp option [:rfc:`5213#section-8.8`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |      Type     |   Length      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                          Timestamp                            +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            This is **not** the :rfc:`1305` NTP timestamp that
            :meth:`_read_opt_mesg_id` reads, and the two must not be conflated.
            :rfc:`5213#section-8.8` counts seconds from the UNIX epoch, not NTP's
            1900 one, and splits the 64 bits 48/16 rather than 32/32. Reading it
            as an NTP timestamp would be wrong in both the epoch and the field
            widths, which is why it gets its own
            :class:`~pcapkit.protocols.internet.mh.PMIPv6Timestamp`.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 8:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        seconds = schema.timestamp['seconds']
        fraction = schema.timestamp['fraction']

        data = Data_TimestampOption(
            type=schema.type,
            length=schema.length + 2,
            timestamp=datetime.datetime.fromtimestamp(
                seconds + fraction / 65536, tz=datetime.timezone.utc),
            pmip_timestamp=PMIPv6Timestamp(seconds, fraction),
        )
        return data

    def _read_opt_restart(self, schema: 'Schema_RestartCounterOption', *,
                          options: 'Option') -> 'Data_RestartCounterOption':
        """Read MH restart counter option.

        Structure of MH Restart Counter option [:rfc:`5847#section-3.4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |      Type     |     Length    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                       Restart Counter                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            :rfc:`5847#section-3.4` says this option is valid only in a heartbeat
            *response*. That is a constraint on the sender rather than on the wire
            format, so it is not enforced here -- a capture carries whatever it
            carries.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_RestartCounterOption(
            type=schema.type,
            length=schema.length + 2,
            counter=schema.counter,
        )
        return data

    def _read_opt_ipv4_hoa(self, schema: 'Schema_IPv4HomeAddressOption', *,
                           options: 'Option') -> 'Data_IPv4HomeAddressOption':
        """Read MH IPv4 home address option.

        Structure of MH IPv4 Home Address option [:rfc:`5555#section-3.1.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type        |   Length      |Prefix-len |P|    Reserved     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                     IPv4 home address                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            A prefix length of ``32`` means a single address rather than a prefix,
            and ``0`` is invalid [:rfc:`5555#section-3.1.1`].

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        prefix_length = schema.flags['prefix_length']
        if prefix_length == 0 or prefix_length > 32:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_IPv4HomeAddressOption(
            type=schema.type,
            length=schema.length + 2,
            prefix_length=prefix_length,
            address=schema.address,
            request_prefix=bool(schema.flags['P']),
        )
        return data

    def _read_opt_ipv4_ack(self, schema: 'Schema_IPv4AddressAcknowledgementOption', *,
                           options: 'Option') -> 'Data_IPv4AddressAcknowledgementOption':
        """Read MH IPv4 address acknowledgement option.

        Structure of MH IPv4 Address Acknowledgement option
        [:rfc:`5555#section-3.2.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |   Status      |Pref-len   |Res|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                      IPv4 home address                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The status field draws from the *DSMIPv6 IPv4 Home Address Option
            Status Codes* registry of :rfc:`5555#section-8`, which despite its
            name governs **this** option rather than the IPv4 home address option.
            It is not the registry the similarly shaped IPv4 Home Address Reply
            option of :rfc:`5844` uses: that one has no value ``133``. Nor is it
            the pseudo-home-address registry of :rfc:`5726` that
            :class:`~pcapkit.const.mh.ack_status_code.ACKStatusCode` carries,
            whose name is the more obvious trap of the three.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_IPv4AddressAcknowledgementOption(
            type=schema.type,
            length=schema.length + 2,
            status=schema.status,
            prefix_length=schema.flags['prefix_length'],
            address=schema.address,
        )
        return data

    def _read_opt_nat(self, schema: 'Schema_NATDetectionOption', *,
                      options: 'Option') -> 'Data_NATDetectionOption':
        """Read MH NAT detection option.

        Structure of MH NAT Detection option [:rfc:`5555#section-3.2.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |F|          Reserved           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                      Refresh time                             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            A refresh time of ``0`` means the field is to be ignored, and all ones
            that no keep-alives are needed [:rfc:`5555#section-3.2.2`]. Both are
            representable as a :class:`~datetime.timedelta`, so the raw value is
            recoverable from it without being stored twice.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_NATDetectionOption(
            type=schema.type,
            length=schema.length + 2,
            force=bool(schema.flags['F']),
            refresh=datetime.timedelta(seconds=schema.refresh),
        )
        return data

    def _read_opt_ipv4_coa(self, schema: 'Schema_IPv4CareofAddressOption', *,
                           options: 'Option') -> 'Data_IPv4CareofAddressOption':
        """Read MH IPv4 care-of address option.

        Structure of MH IPv4 Care-of Address option [:rfc:`5555#section-3.1.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type        |   Length      |         Reserved              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                     IPv4 Care-of address                      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            Unlike the IPv4 home address option, the whole half-word before the
            address is reserved -- there is no prefix length and no ``P`` flag
            carved out of it.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_IPv4CareofAddressOption(
            type=schema.type,
            length=schema.length + 2,
            address=schema.address,
        )
        return data

    def _read_opt_gre(self, schema: 'Schema_GREKeyOption', *,
                      options: 'Option') -> 'Data_GREKeyOption':
        """Read MH GRE key option.

        Structure of MH GRE Key option [:rfc:`5845#section-6.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                      GRE Key Identifier                       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The key identifier is present only when the option length is ``6``; a
            length of ``2`` says the option carries none
            [:rfc:`5845#section-6.1`]. No flag announces that, so the length is
            the only thing to branch on, and any other length is malformed.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length not in (2, 6):
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_GREKeyOption(
            type=schema.type,
            length=schema.length + 2,
            key=schema.key if schema.length == 6 else None,
        )
        return data

    def _read_opt_bid(self, schema: 'Schema_BindingIdentifierOption', *,
                      options: 'Option') -> 'Data_BindingIdentifierOption':
        """Read MH binding identifier (BID) option.

        Structure of MH Binding Identifier option [:rfc:`5648#section-4.3`, as
        updated by :rfc:`6089#section-4.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |   Type = 35   |     Length    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |       Binding ID (BID)        |     Status    |H|   BID-PRI   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------------------------+
           +                                                               +
           :                 IPv4 or IPv6 Care-of Address (CoA)            :
           +                                                               +
           +---------------------------------------------------------------+

        Note:
            The care-of address is absent for a length of ``4``, an IPv4 address
            for ``8`` and an IPv6 address for ``20``; no other length is valid and
            the option carries no address-family flag, so the length is the only
            thing to branch on [:rfc:`5648#section-4.3`].

            :rfc:`6089#section-4.1` renames the seven bits below the ``H`` flag
            from ``Reserved`` to ``BID-PRI``, a binding priority in which ``0``
            marks a sender predating :rfc:`6089`. The newer reading is used, since
            a zero reads identically either way.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length not in (4, 8, 20):
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_BindingIdentifierOption(
            type=schema.type,
            length=schema.length + 2,
            bid=schema.bid,
            status=schema.status,
            simultaneous=bool(schema.flags['H']),
            bid_pri=schema.flags['BID_PRI'],
            address=cast('Optional[IPv4Address | IPv6Address]', schema.address),
        )
        return data

    def _read_opt_ipv4_hoa_req(self, schema: 'Schema_IPv4HomeAddressRequestOption', *,
                               options: 'Option') -> 'Data_IPv4HomeAddressRequestOption':
        """Read MH IPv4 home address request option.

        Structure of MH IPv4 Home Address Request option
        [:rfc:`5844#section-3.3.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |   Length      |Prefix-len |      Reserved     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                     IPv4 home address                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            Unlike the IPv4 home address option of :rfc:`5555#section-3.1.1`,
            which this otherwise resembles, there is no ``P`` flag -- the reserved
            field is 10 bits rather than 9.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_IPv4HomeAddressRequestOption(
            type=schema.type,
            length=schema.length + 2,
            prefix_length=schema.flags['prefix_length'],
            address=schema.address,
        )
        return data

    def _read_opt_ipv4_hoa_rep(self, schema: 'Schema_IPv4HomeAddressReplyOption', *,
                               options: 'Option') -> 'Data_IPv4HomeAddressReplyOption':
        """Read MH IPv4 home address reply option.

        Structure of MH IPv4 Home Address Reply option [:rfc:`5844#section-3.3.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |   Status      |Pref-len   |Res|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                      IPv4 home address                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The status draws from the *IPv4 Home Address Reply Status Codes*
            registry of :rfc:`5844#section-6`, which is **not** the DSMIPv6 one the
            identically shaped IPv4 address acknowledgement option of :rfc:`5555`
            uses -- that registry additionally defines ``133``.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_IPv4HomeAddressReplyOption(
            type=schema.type,
            length=schema.length + 2,
            status=schema.status,
            prefix_length=schema.flags['prefix_length'],
            address=schema.address,
        )
        return data

    def _read_opt_ipv4_router(self, schema: 'Schema_IPv4DefaultRouterAddressOption', *,
                              options: 'Option') -> 'Data_IPv4DefaultRouterAddressOption':
        """Read MH IPv4 default-router address option.

        Structure of MH IPv4 Default-Router Address option
        [:rfc:`5844#section-3.3.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |         Reserved (R)          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  IPv4 Default-Router Address                  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_IPv4DefaultRouterAddressOption(
            type=schema.type,
            length=schema.length + 2,
            address=schema.address,
        )
        return data

    def _read_opt_ipv4_dhcp(self, schema: 'Schema_IPv4DHCPSupportModeOption', *,
                            options: 'Option') -> 'Data_IPv4DHCPSupportModeOption':
        """Read MH IPv4 DHCP support mode option.

        Structure of MH IPv4 DHCP Support Mode option [:rfc:`5844#section-3.3.4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |    Reserved (R)             |S|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The ``S`` bit is the **last** bit of the option, not the first -- the
            reserved field precedes it rather than following it, which is the
            other way round from every other flag in this module.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 2:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_IPv4DHCPSupportModeOption(
            type=schema.type,
            length=schema.length + 2,
            mode=Enum_DHCPSupportMode(schema.flags['S']),
        )
        return data

    def _read_opt_cr(self, schema: 'Schema_ContextRequestOption', *,
                     options: 'Option') -> 'Data_ContextRequestOption':
        """Read MH context request option.

        Structure of MH Context Request option [:rfc:`5949#section-6.2.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+---------------+---------------+
           |  Option-Type  | Option-Length |           Reserved            |
           +---------------+---------------+-------------------------------+
           |  Req-type-1   | Req-length-1  |  Req-type-2   | Req-length-2  |
           +---------------------------------------------------------------+
           |  Req-type-3   | Req-length-3  |          Req-option-3         |
           +---------------------------------------------------------------+
           |                              ...                              |

        Note:
            The requested types are drawn from the mobility option registry
            itself, so a request for a vendor specific option (type ``19``) is
            followed by five octets naming the vendor and sub-type, whereas a
            request for a home network prefix (type ``22``) carries a request
            length of zero. There is neither a count field nor a terminator: the
            list runs to the end of the option.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length < 2:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        requests = []  # type: list[Data_ContextRequest]
        buffer = schema.requests
        index = 0
        while index < len(buffer):
            if index + 2 > len(buffer):
                raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

            req_type, req_len = buffer[index], buffer[index + 1]
            value = buffer[index + 2:index + 2 + req_len]
            if len(value) != req_len:
                raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

            requests.append(Data_ContextRequest(
                type=Enum_Option.get(req_type),
                length=req_len,
                value=value,
            ))
            index += 2 + req_len

        data = Data_ContextRequestOption(
            type=schema.type,
            length=schema.length + 2,
            requests=tuple(requests),
        )
        return data

    def _read_opt_lmaa(self, schema: 'Schema_LMAAddressOption', *,
                       options: 'Option') -> 'Data_LMAAddressOption':
        """Read MH local mobility anchor address option.

        Structure of MH Local Mobility Anchor Address option
        [:rfc:`5949#section-6.2.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Option-Type  | Option-Length |  Option-Code  |   Reserved    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |              Local Mobility Anchor Address ...                |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        The option codes are enumerated in
        :class:`~pcapkit.protocols.internet.mh.LMAAddressCode`, which is local to
        this module because :rfc:`5949` defines them inline with no IANA registry
        behind them.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length not in (6, 18):
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_LMAAddressOption(
            type=schema.type,
            length=schema.length + 2,
            code=LMAAddressCode(schema.code),
            address=schema.address,
        )
        return data

    def _read_opt_mn_lla_iid(self, schema: 'Schema_MNLLAIIDOption', *,
                             options: 'Option') -> 'Data_MNLLAIIDOption':
        """Read MH mobile node link-local address interface identifier option.

        Structure of MH Mobile Node Link-local Address Interface Identifier option
        [:rfc:`5949#section-6.2.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Option-Type   | Option-Length |            Reserved           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                      Interface Identifier                     +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 10:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_MNLLAIIDOption(
            type=schema.type,
            length=schema.length + 2,
            iid=schema.iid,
        )
        return data

    def _read_opt_transient(self, schema: 'Schema_TransientBindingOption', *,
                            options: 'Option') -> 'Data_TransientBindingOption':
        """Read MH transient binding option.

        Structure of MH Transient Binding option [:rfc:`6058#section-5.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |    Type       |     Length    | Reserved    |L|   Lifetime    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The lifetime is in units of **100 milliseconds**, which is unlike every
            other lifetime in this module [:rfc:`6058#section-5.1`]. The ``L`` flag
            is the last bit of the third octet, with the seven reserved bits above
            rather than below it.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 2:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_TransientBindingOption(
            type=schema.type,
            length=schema.length + 2,
            late=bool(schema.flags['L']),
            lifetime=datetime.timedelta(milliseconds=schema.lifetime * 100),
        )
        return data

    def _read_opt_fs(self, schema: 'Schema_FlowSummaryOption', *,
                     options: 'Option') -> 'Data_FlowSummaryOption':
        """Read MH flow summary mobility option.

        Structure of MH Flow Summary mobility option [:rfc:`6089#section-4.2.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Option Type   |  Option Len   |              FID              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     FID  ........
           +-+-+-+-+-+-+-+-+-+-+-

        Note:
            :rfc:`6089#section-8` prints the type codes of this option and the flow
            identification option the wrong way round, contradicting both its own
            figures and the IANA registry. The figures and the registry agree that
            the flow summary option is type ``44``, which is what is registered
            here.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length % 2 != 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_FlowSummaryOption(
            type=schema.type,
            length=schema.length + 2,
            fid=tuple(schema.fid),
        )
        return data

    def _read_fid_suboptions(
        self, suboptions_schema: 'list[Schema_FlowIdentificationSuboption]',
    ) -> 'FlowIDSuboption':
        """Read MH flow identification sub-options.

        Structure of MH flow identification sub-option [:rfc:`6089#section-4.2.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Sub-Opt Type  |Sub-Opt Length |   Sub-Option Data...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        These are sub-options of one mobility option rather than mobility options
        in their own right, so they are dispatched here rather than through
        :attr:`self.__option__ <MH.__option__>`.

        Note:
            Dispatch is on the sub-option **type code**, never on ``isinstance`` of
            the schema class, and that is load-bearing rather than a matter of
            taste. Every schema class descends from
            :class:`collections.abc.Mapping`, and on Python 3.10 and older they do
            **not** each get their own ``_abc_impl`` -- they share
            :class:`~pcapkit.protocols.schema.schema.Schema`'s. One
            :class:`abc.ABCMeta` cache therefore serves the whole family, and it is
            keyed only on the class being *tested*, not on the class being tested
            *against*. So one ``issubclass`` answer poisons every later question
            about the same class:

            .. code-block:: python

               >>> issubclass(ANIGeoLocationSuboption, Schema)                 # True, cached
               True
               >>> issubclass(ANIGeoLocationSuboption, ANINetworkIdentifierSuboption)
               True   # wrong -- the cached True for Schema is handed back

            The wrong answer goes both ways: a correct ``False`` against a sibling
            then makes ``isinstance(sub, Schema)`` ``False``, which is what
            :meth:`ListField.pack
            <pcapkit.corekit.fields.collections.ListField.pack>` consults, so
            packing a perfectly good option fails with
            :exc:`~pcapkit.utilities.exceptions.FieldValueError`. Python 3.11 and
            newer give each class its own cache and the checks behave, which is why
            this was invisible on a modern interpreter.

            The code is on the wire and the registry keys on it, so it is both the
            cheaper discriminator and the only one that cannot be poisoned. The
            same reasoning applies to :meth:`_read_ani_suboptions`,
            :meth:`_read_qos_attributes`, :meth:`_read_lcmp_suboptions` and their
            four constructor counterparts.

        Args:
            suboptions_schema: Parsed sub-option schemas.

        Returns:
            Parsed sub-option data.

        """
        suboptions = OrderedMultiDict()  # type: FlowIDSuboption

        for schema in suboptions_schema:
            code = schema.type

            if code in (Enum_FlowIDSuboption.Pad, Enum_FlowIDSuboption.PadN):
                pad = cast('Schema_PadFlowIdentificationSuboption', schema)
                size = 1 if code == Enum_FlowIDSuboption.Pad else pad.length + 2
                data = Data_PadFlowIdentificationSuboption(
                    type=code,
                    length=size,
                )  # type: Data_FlowIdentificationSuboption
            elif code == Enum_FlowIDSuboption.BID_Reference:
                bid_ref = cast('Schema_BIDReferenceSuboption', schema)
                data = Data_BIDReferenceSuboption(
                    type=code,
                    length=bid_ref.length + 2,
                    bid=tuple(bid_ref.bid),
                )
            elif code == Enum_FlowIDSuboption.Traffic_Selector:
                selector = cast('Schema_TrafficSelectorSuboption', schema)
                data = Data_TrafficSelectorSuboption(
                    type=code,
                    length=selector.length + 2,
                    ts_format=selector.ts_format,
                    selector=selector.selector,
                )
            elif code == Enum_FlowIDSuboption.Flow_Binding_Action:
                action = cast('Schema_FlowBindingActionSuboption', schema)
                data = Data_FlowBindingActionSuboption(
                    type=code,
                    length=action.length + 2,
                    action=action.action,
                )
            elif code == Enum_FlowIDSuboption.Target_Care_of_Address:
                target = cast('Schema_TargetCareofAddressSuboption', schema)
                data = Data_TargetCareofAddressSuboption(
                    type=code,
                    length=target.length + 2,
                    address=target.address,
                )
            else:
                unknown = cast('Schema_UnassignedFlowIdentificationSuboption', schema)
                data = Data_UnassignedFlowIdentificationSuboption(
                    type=code,
                    length=unknown.length + 2,
                    data=unknown.data,
                )

            suboptions.add(code, data)

        return suboptions

    def _read_opt_fid(self, schema: 'Schema_FlowIdentificationOption', *,
                      options: 'Option') -> 'Data_FlowIdentificationOption':
        """Read MH flow identification mobility option.

        Structure of MH Flow Identification mobility option
        [:rfc:`6089#section-4.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Option Type   |  Option Len   |              FID              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |              FID-PRI          |   Reserved    |     Status    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Sub-options (optional) ...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The status draws from the *Flow Identification Mobility Option Status
            Codes* registry, which is neither the general mobility status codes nor
            the flow binding acknowledgement ones -- three similarly named
            registries that must not be confused.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length < 6:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_FlowIdentificationOption(
            type=schema.type,
            length=schema.length + 2,
            fid=schema.fid,
            fid_pri=schema.fid_pri,
            status=schema.status,
            suboptions=self._read_fid_suboptions(schema.suboptions),
        )
        return data

    def _read_opt_rc(self, schema: 'Schema_RedirectCapabilityOption', *,
                     options: 'Option') -> 'Data_RedirectCapabilityOption':
        """Read MH redirect-capability mobility option.

        Structure of MH Redirect-Capability mobility option
        [:rfc:`6463#section-4.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Option Type   | Option Length |          Reserved             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 2:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_RedirectCapabilityOption(
            type=schema.type,
            length=schema.length + 2,
        )
        return data

    def _read_opt_redirect(self, schema: 'Schema_RedirectOption', *,
                           options: 'Option') -> 'Data_RedirectOption':
        """Read MH redirect mobility option.

        Structure of MH Redirect mobility option [:rfc:`6463#section-4.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Option Type   | Option Length |K|N|      Reserved             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           |                  Optional IPv6 r2LMA Address                  |
           |                                                               |
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  Optional IPv4 r2LMA Address                  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            :rfc:`6463#section-4.2` forbids ``K`` and ``N`` from being both set and
            both clear, so exactly one address is present and the option length is
            18 or 6 accordingly. The two encodings of the same fact are checked
            against each other here, since a disagreement means the option cannot
            be read either way.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        ipv6_flag = bool(schema.flags['K'])
        ipv4_flag = bool(schema.flags['N'])

        if ipv6_flag == ipv4_flag:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')
        if schema.length != (18 if ipv6_flag else 6):
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_RedirectOption(
            type=schema.type,
            length=schema.length + 2,
            ipv6=schema.ipv6,
            ipv4=schema.ipv4,
        )
        return data

    def _read_opt_load(self, schema: 'Schema_LoadInformationOption', *,
                       options: 'Option') -> 'Data_LoadInformationOption':
        """Read MH load information mobility option.

        Structure of MH Load Information mobility option [:rfc:`6463#section-4.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Option Type   | Option Length |          Priority             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                        Sessions in Use                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                        Maximum Sessions                       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Used Capacity                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                        Maximum Capacity                       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The two capacity fields are in **kilobytes** per second, unlike the
            quality-of-service bit rates, which are in bits per second
            [:rfc:`6463#section-4.3`].

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 18:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_LoadInformationOption(
            type=schema.type,
            length=schema.length + 2,
            priority=schema.priority,
            sessions_in_use=schema.sessions_in_use,
            max_sessions=schema.max_sessions,
            used_capacity=schema.used_capacity,
            max_capacity=schema.max_capacity,
        )
        return data

    def _read_opt_alt_ipv4_coa(self, schema: 'Schema_AlternateIPv4CareofAddressOption', *,
                               options: 'Option') -> 'Data_AlternateIPv4CareofAddressOption':
        """Read MH alternate IPv4 care-of address option.

        Structure of MH Alternate IPv4 Care-of Address option
        [:rfc:`6463#section-4.4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           | Option Type   | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                 Alternate IPv4 Care-of Address                |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_AlternateIPv4CareofAddressOption(
            type=schema.type,
            length=schema.length + 2,
            address=schema.address,
        )
        return data

    def _read_opt_mn_group(self, schema: 'Schema_MNGroupIdentifierOption', *,
                           options: 'Option') -> 'Data_MNGroupIdentifierOption':
        """Read MH mobile node group identifier option.

        Structure of MH Mobile Node Group Identifier option
        [:rfc:`6602#section-4.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |  Sub-type   |    Reserved     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  Mobile Node Group Identifier                 |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_MNGroupIdentifierOption(
            type=schema.type,
            length=schema.length + 2,
            subtype=schema.subtype,
            group_id=schema.group_id,
        )
        return data

    def _read_opt_mag_addr(self, schema: 'Schema_MAGIPv6AddressOption', *,
                           options: 'Option') -> 'Data_MAGIPv6AddressOption':
        """Read MH MAG IPv6 address option.

        Structure of MH MAG IPv6 Address option [:rfc:`6705#section-11.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |   Reserved    | Address Length|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                       MAG IPv6 Address                        +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The option is modelled on the home network prefix option, which is why
            it carries an address *length* field at all; :rfc:`6705#section-11.1`
            requires it to be ``128``, since a full address is always carried.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 18:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_MAGIPv6AddressOption(
            type=schema.type,
            length=schema.length + 2,
            address_length=schema.address_length,
            address=schema.address,
        )
        return data

    def _read_ani_suboptions(
        self, suboptions_schema: 'list[Schema_ANISuboption]',
    ) -> 'ANISuboption':
        """Read MH access network identifier sub-options.

        Structure of MH access network identifier sub-option
        [:rfc:`6757#section-3.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |    ANI Type   | ANI Length    |         Option Data           ~
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        The geo-location degrees of :rfc:`6757#section-3.1.2` are 24-bit
        **two's-complement** fixed-point values with nine integer bits. A
        :class:`~pcapkit.corekit.fields.strings.BitField` reads them unsigned, so
        the sign is applied here, and both the decoded degrees and the raw signed
        integers are recorded -- the latter so that the exact wire value survives
        a round trip through the data model.

        Note:
            Dispatch is on the sub-option type code rather than on ``isinstance``
            of the schema class, for the reason given in
            :meth:`_read_fid_suboptions`.

        Args:
            suboptions_schema: Parsed sub-option schemas.

        Returns:
            Parsed sub-option data.

        """
        suboptions = OrderedMultiDict()  # type: ANISuboption

        for schema in suboptions_schema:
            code = schema.type

            if code == Enum_ANISuboption.Network_Identifier:
                net = cast('Schema_ANINetworkIdentifierSuboption', schema)
                data = Data_ANINetworkIdentifierSuboption(
                    type=code,
                    length=net.length + 2,
                    utf8=bool(net.flags['E']),
                    net_name=net.net_name,
                    ap_name=net.ap_name,
                )  # type: Data_ANISuboption
            elif code == Enum_ANISuboption.Geo_Location:
                geo = cast('Schema_ANIGeoLocationSuboption', schema)
                raw_lat = self._decode_signed(geo.location['latitude'], 24)
                raw_lon = self._decode_signed(geo.location['longitude'], 24)
                data = Data_ANIGeoLocationSuboption(
                    type=code,
                    length=geo.length + 2,
                    latitude=raw_lat / 2 ** 15,
                    longitude=raw_lon / 2 ** 15,
                    raw_latitude=raw_lat,
                    raw_longitude=raw_lon,
                )
            elif code == Enum_ANISuboption.Operator_Identifier:
                operator = cast('Schema_ANIOperatorIdentifierSuboption', schema)
                data = Data_ANIOperatorIdentifierSuboption(
                    type=code,
                    length=operator.length + 2,
                    op_id_type=operator.op_id_type,
                    identifier=operator.identifier,
                )
            elif code == Enum_ANISuboption.Civic_Location:
                civic = cast('Schema_ANICivicLocationSuboption', schema)
                data = Data_ANICivicLocationSuboption(
                    type=code,
                    length=civic.length + 2,
                    format=civic.format,
                    location=civic.location,
                )
            elif code == Enum_ANISuboption.MAG_Group_Identifier:
                group = cast('Schema_ANIMAGGroupIdentifierSuboption', schema)
                data = Data_ANIMAGGroupIdentifierSuboption(
                    type=code,
                    length=group.length + 2,
                    group_id=group.group_id,
                )
            elif code == Enum_ANISuboption.ANI_Update_Timer:
                timer = cast('Schema_ANIUpdateTimerSuboption', schema)
                data = Data_ANIUpdateTimerSuboption(
                    type=code,
                    length=timer.length + 2,
                    timer=datetime.timedelta(seconds=timer.timer * 4),
                )
            else:
                unknown = cast('Schema_UnassignedANISuboption', schema)
                data = Data_UnassignedANISuboption(
                    type=code,
                    length=unknown.length + 2,
                    data=unknown.data,
                )

            suboptions.add(code, data)

        return suboptions

    @staticmethod
    def _decode_signed(value: 'int', width: 'int') -> 'int':
        """Reinterpret an unsigned integer as a two's-complement signed one.

        Args:
            value: Unsigned value as read from the wire.
            width: Field width, in bits.

        Returns:
            The signed value the same bits denote.

        Note:
            :class:`~pcapkit.corekit.fields.strings.BitField` reads a sub-field as
            an unsigned integer, since that is what almost every bit-packed field
            in the mobility header is. The geo-location degrees of
            :rfc:`6757#section-3.1.2` are the exception, so they are converted
            here rather than by teaching the field about signedness -- a change
            that would touch every other user of it.

        """
        sign_bit = 1 << (width - 1)
        return value - (1 << width) if value & sign_bit else value

    def _read_opt_ani(self, schema: 'Schema_AccessNetworkIdentifierOption', *,
                      options: 'Option') -> 'Data_AccessNetworkIdentifierOption':
        """Read MH access network identifier option.

        Structure of MH Access Network Identifier option [:rfc:`6757#section-3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                          ...      ANI Sub-option(s) ...                   ~
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            Unlike most options carrying sub-options, this one has **no** reserved
            octet between its own length and the first sub-option
            [:rfc:`6757#section-3`], and it must carry at least one.

            IANA names the sub-option registry "Access Network *Information*"
            while the RFC's prose says "Identifier"; they are the same registry.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length == 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_AccessNetworkIdentifierOption(
            type=schema.type,
            length=schema.length + 2,
            suboptions=self._read_ani_suboptions(schema.suboptions),
        )
        return data

    def _read_opt_offload(self, schema: 'Schema_IPv4TrafficOffloadSelectorOption', *,
                          options: 'Option') -> 'Data_IPv4TrafficOffloadSelectorOption':
        """Read MH IPv4 traffic offload selector option.

        Structure of MH IPv4 Traffic Offload Selector option
        [:rfc:`6909#section-3.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |      Type     |   Length      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |M|                         Reserved                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  Traffic Selector Sub-option   ...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The traffic selector it carries is the *flow identification*
            sub-option of :rfc:`6089#section-4.2.1.4`, so it is read through the
            same sub-option registry rather than through one of its own. It is
            optional in a proxy binding update and mandatory in a proxy binding
            acknowledgement, hence a collection rather than a single value.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_IPv4TrafficOffloadSelectorOption(
            type=schema.type,
            length=schema.length + 2,
            mode=bool(schema.flags['M']),
            selector=self._read_fid_suboptions(schema.selector),
        )
        return data

    def _read_opt_mcast_sel(self, schema: 'Schema_DynamicIPMulticastSelectorOption', *,
                            options: 'Option') -> 'Data_DynamicIPMulticastSelectorOption':
        """Read MH dynamic IP multicast selector option.

        Structure of MH Dynamic IP Multicast Selector option
        [:rfc:`7028#section-5.1.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |      Type     |     Length    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Protocol    |M| Reserved  |Nr of Mcast Address Records (N)|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                  Multicast Address Record [1]                 +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           .                               .                               .
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                  Multicast Address Record [N]                 +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The address records are :rfc:`3810#section-5.2` MLD or
            :rfc:`3376#section-4.2` IGMP structures. They belong to those protocols
            rather than to the mobility header, and each is self-describing through
            its own auxiliary-data length and source count, so they are recorded
            opaquely here rather than half-decoded. :attr:`protocol` says which of
            the two they are: ``143`` for MLDv2, ``131`` for MLDv1.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_DynamicIPMulticastSelectorOption(
            type=schema.type,
            length=schema.length + 2,
            protocol=schema.protocol,
            mode=bool(schema.flags['M']),
            records=schema.records,
            data=schema.data,
        )
        return data

    def _read_opt_dmnp(self, schema: 'Schema_DelegatedMNPOption', *,
                       options: 'Option') -> 'Data_DelegatedMNPOption':
        """Read MH delegated mobile network prefix option.

        Structure of MH Delegated Mobile Network Prefix option
        [:rfc:`7148#section-4.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |V|  Reserved   | Prefix Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           .                                                               .
           +           IPv4 or IPv6 Delegated Mobile Network Prefix        +
           |                         (DMNP)                                |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            Unlike the binding identifier and target care-of address, this option
            *does* carry an address-family flag, so the ``V`` bit rather than the
            option length is what selects the prefix width
            [:rfc:`7148#section-4.1`]. The two are checked against each other,
            since a disagreement leaves the option unreadable.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        ipv4 = bool(schema.flags['V'])
        if schema.length != (6 if ipv4 else 18):
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_DelegatedMNPOption(
            type=schema.type,
            length=schema.length + 2,
            ipv4=ipv4,
            prefix_length=schema.prefix_length,
            prefix=schema.prefix,
        )
        return data

    def _read_opt_ams4(self, schema: 'Schema_ActiveMulticastSubscriptionIPv4Option', *,
                       options: 'Option') -> 'Data_ActiveMulticastSubscriptionIPv4Option':
        """Read MH active multicast subscription IPv4 option.

        Structure of MH Active Multicast Subscription IPv4 option
        [:rfc:`7161#section-6.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                          |      Type     |     Length    |   IGMP Type   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                  Multicast Membership Context                 +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The membership context is an IGMP group address (:rfc:`1112`,
            :rfc:`2236`) or an IGMPv3 group record (:rfc:`3376#section-4.2`),
            which belong to IGMP rather than to the mobility header, so they are
            recorded opaquely. :attr:`igmp_type` says which: ``0x12`` IGMPv1,
            ``0x16`` IGMPv2, ``0x22`` IGMPv3.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length < 1:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_ActiveMulticastSubscriptionIPv4Option(
            type=schema.type,
            length=schema.length + 2,
            igmp_type=schema.igmp_type,
            context=schema.context,
        )
        return data

    def _read_opt_ams6(self, schema: 'Schema_ActiveMulticastSubscriptionIPv6Option', *,
                       options: 'Option') -> 'Data_ActiveMulticastSubscriptionIPv6Option':
        """Read MH active multicast subscription IPv6 option.

        Structure of MH Active Multicast Subscription IPv6 option
        [:rfc:`7161#section-4.1.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                          |      Type     |     Length    |    MLD Type   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                  Multicast Membership Context                 +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            For MLDv2 the context is an :rfc:`3810#section-5.2` multicast address
            record; for MLDv1 it is a reserved word followed by a multicast address
            [:rfc:`7161#section-4.1.3`]. Both belong to MLD, so the context is
            recorded opaquely and :attr:`mld_type` says which form it is in.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length < 1:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_ActiveMulticastSubscriptionIPv6Option(
            type=schema.type,
            length=schema.length + 2,
            mld_type=schema.mld_type,
            context=schema.context,
        )
        return data

    def _read_qos_attributes(
        self, attributes_schema: 'list[Schema_QoSAttribute]',
    ) -> 'QoSAttribute':
        """Read MH quality-of-service attributes.

        Structure of MH quality-of-service attribute [:rfc:`7222#section-4.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |    Type       |     Length    |           Value               ~
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            Every bit rate here is in **bits** per second [:rfc:`7222#section-4.2.1`],
            not the kilobytes per second of the load information option's capacity
            fields.

            Dispatch is on the attribute type code rather than on ``isinstance`` of
            the schema class, for the reason given in
            :meth:`_read_fid_suboptions`.

        Args:
            attributes_schema: Parsed attribute schemas.

        Returns:
            Parsed attribute data.

        """
        attributes = OrderedMultiDict()  # type: QoSAttribute

        for schema in attributes_schema:
            code = schema.type

            if code in (Enum_QoSAttribute.Per_Session_Agg_Max_DL_Bit_Rate,
                        Enum_QoSAttribute.Per_Session_Agg_Max_UL_Bit_Rate):
                session = cast('Schema_PerSessionBitRateAttribute', schema)
                data = Data_PerSessionBitRateAttribute(
                    type=code,
                    length=session.length + 2,
                    service=bool(session.flags['S']),
                    exclude=bool(session.flags['E']),
                    rate=session.rate,
                )  # type: Data_QoSAttribute
            elif code in (Enum_QoSAttribute.Per_MN_Agg_Max_DL_Bit_Rate,
                          Enum_QoSAttribute.Per_MN_Agg_Max_UL_Bit_Rate,
                          Enum_QoSAttribute.Aggregate_Max_DL_Bit_Rate,
                          Enum_QoSAttribute.Aggregate_Max_UL_Bit_Rate,
                          Enum_QoSAttribute.Guaranteed_DL_Bit_Rate,
                          Enum_QoSAttribute.Guaranteed_UL_Bit_Rate):
                rate = cast('Schema_BitRateAttribute', schema)
                data = Data_BitRateAttribute(
                    type=code,
                    length=rate.length + 2,
                    rate=rate.rate,
                )
            elif code == Enum_QoSAttribute.Allocation_Retention_Priority:
                arp = cast('Schema_AllocationRetentionPriorityAttribute', schema)
                data = Data_AllocationRetentionPriorityAttribute(
                    type=code,
                    length=arp.length + 2,
                    priority_level=arp.priority['PL'],
                    preemption_capability=arp.priority['PC'],
                    preemption_vulnerability=arp.priority['PV'],
                )
            elif code == Enum_QoSAttribute.QoS_Traffic_Selector:
                selector = cast('Schema_QoSTrafficSelectorAttribute', schema)
                data = Data_QoSTrafficSelectorAttribute(
                    type=code,
                    length=selector.length + 2,
                    ts_format=selector.ts_format,
                    selector=selector.selector,
                )
            elif code == Enum_QoSAttribute.QoS_Vendor_Specific_Attribute:
                vendor = cast('Schema_QoSVendorSpecificAttribute', schema)
                data = Data_QoSVendorSpecificAttribute(
                    type=code,
                    length=vendor.length + 2,
                    vendor=vendor.vendor,
                    subtype=vendor.subtype,
                    data=vendor.data,
                )
            else:
                unknown = cast('Schema_UnassignedQoSAttribute', schema)
                data = Data_UnassignedQoSAttribute(
                    type=code,
                    length=unknown.length + 2,
                    data=unknown.data,
                )

            attributes.add(code, data)

        return attributes

    def _read_opt_qos(self, schema: 'Schema_QualityOfServiceOption', *,
                      options: 'Option') -> 'Data_QualityOfServiceOption':
        """Read MH quality-of-service option.

        Structure of MH Quality-of-Service option [:rfc:`7222#section-4.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |    Length     |     SR-ID     |       TC      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |       OC      |                   Reserved                    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           ~                        QoS Attribute(s)                       ~
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The traffic class octet is a 6-bit differentiated services code point
            with two reserved bits below it, so only the code point is carried into
            the data model.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length < 6:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_QualityOfServiceOption(
            type=schema.type,
            length=schema.length + 2,
            sr_id=schema.sr_id,
            dscp=schema.tc >> 2,
            oc=schema.oc,
            attributes=self._read_qos_attributes(schema.attributes),
        )
        return data

    def _read_opt_lma_up(self, schema: 'Schema_LMAUserPlaneAddressOption', *,
                         options: 'Option') -> 'Data_LMAUserPlaneAddressOption':
        """Read MH LMA user-plane address option.

        Structure of MH LMA User-Plane Address option [:rfc:`7389#section-4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           .                                                               .
           +                     LMA User-Plane Address                    +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The address may legitimately be **absent**: a mobile access gateway
            sends the option with no address, or with an all-zero one, purely to
            say which transport it wants [:rfc:`7389#section-4`]. Only a local
            mobility anchor's reply is required to carry a real address.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length not in (2, 6, 18):
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_LMAUserPlaneAddressOption(
            type=schema.type,
            length=schema.length + 2,
            address=cast('Optional[IPv4Address | IPv6Address]',
                         schema.address if schema.length != 2 else None),
        )
        return data

    def _read_opt_mcast(self, schema: 'Schema_MulticastMobilityOption', *,
                        options: 'Option') -> 'Data_MulticastMobilityOption':
        """Read MH multicast mobility option.

        Structure of MH Multicast Mobility option [:rfc:`7411#section-5.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |   Length      | Option-Code   |   Reserved    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                    MLD or IGMP Report Payload                 |
           ~                                                               ~
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            This option's length field is **not** the usual octet count.
            :rfc:`7411#section-5.3` measures it in 32-bit *words* and excludes the
            option code and reserved octets as well as the type and length ones, so
            the option occupies ``4 + length * 4`` octets rather than
            ``length + 2``. The option-collection machinery advances by the octets
            the schema actually consumed rather than by the declared length, so the
            unusual unit does not misframe the options that follow -- but it does
            mean :attr:`~pcapkit.protocols.data.internet.mh.Option.length` here is
            the true octet count, computed rather than copied.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        data = Data_MulticastMobilityOption(
            type=schema.type,
            length=schema.length * 4 + 4,
            code=schema.code,
            data=schema.data,
        )
        return data

    def _read_opt_mcast_ack(self, schema: 'Schema_MulticastAcknowledgementOption', *,
                            options: 'Option') -> 'Data_MulticastAcknowledgementOption':
        """Read MH multicast acknowledgement option.

        Structure of MH Multicast Acknowledgement option [:rfc:`7411#section-5.4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |   Length      | Option-Code   |    Status     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |           MLD or IGMP Unsupported Report Payload              |
           ~                                                               ~
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            As with :meth:`_read_opt_mcast`, the length counts 32-bit words and
            excludes the option code and status octets [:rfc:`7411#section-5.4`].

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        data = Data_MulticastAcknowledgementOption(
            type=schema.type,
            length=schema.length * 4 + 4,
            code=schema.code,
            status=schema.status,
            data=schema.data,
        )
        return data

    def _read_lcmp_suboptions(
        self, suboptions_schema: 'list[Schema_LMAControlledMAGSuboption]',
    ) -> 'LMAControlledMAGSuboption':
        """Read MH LMA-controlled MAG parameters sub-options.

        Structure of MH LMA-controlled MAG parameters sub-option
        [:rfc:`8127#section-3.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   LCMP Type   | LCMP Length   |       Sub-Option Data         ~
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            Only the re-registration start time is in units of 4 seconds; every
            other interval in these two sub-options is in whole seconds
            [:rfc:`8127#section-3.1.1`, :rfc:`8127#section-3.1.2`].

            Dispatch is on the sub-option type code rather than on ``isinstance``
            of the schema class, for the reason given in
            :meth:`_read_fid_suboptions`.

        Args:
            suboptions_schema: Parsed sub-option schemas.

        Returns:
            Parsed sub-option data.

        """
        suboptions = OrderedMultiDict()  # type: LMAControlledMAGSuboption

        for schema in suboptions_schema:
            code = schema.type

            if code == Enum_LMAControlledMAGSuboption.Binding_Re_registration_Control:
                rereg = cast('Schema_BindingReregistrationControlSuboption', schema)
                data = Data_BindingReregistrationControlSuboption(
                    type=code,
                    length=rereg.length + 2,
                    start_time=datetime.timedelta(seconds=rereg.start_time * 4),
                    initial_retransmission=datetime.timedelta(
                        seconds=rereg.initial_retransmission),
                    max_retransmission=datetime.timedelta(seconds=rereg.max_retransmission),
                )  # type: Data_LMAControlledMAGSuboption
            elif code == Enum_LMAControlledMAGSuboption.Heartbeat_Control:
                heartbeat = cast('Schema_HeartbeatControlSuboption', schema)
                data = Data_HeartbeatControlSuboption(
                    type=code,
                    length=heartbeat.length + 2,
                    interval=datetime.timedelta(seconds=heartbeat.interval),
                    retransmission_delay=datetime.timedelta(
                        seconds=heartbeat.retransmission_delay),
                    max_retransmissions=heartbeat.max_retransmissions,
                )
            else:
                unknown = cast('Schema_UnassignedLMAControlledMAGSuboption', schema)
                data = Data_UnassignedLMAControlledMAGSuboption(
                    type=code,
                    length=unknown.length + 2,
                    data=unknown.data,
                )

            suboptions.add(code, data)

        return suboptions

    def _read_opt_lcmp(self, schema: 'Schema_LMAControlledMAGParametersOption', *,
                       options: 'Option') -> 'Data_LMAControlledMAGParametersOption':
        """Read MH LMA-controlled MAG parameters option.

        Structure of MH LMA-Controlled MAG Parameters option
        [:rfc:`8127#section-3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |      Type     |   Length      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                     LCMP Sub-Option(s)                        ~
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            This option is registered to :rfc:`8127`, **not** to :rfc:`7864` --
            the latter defines the flow-mobility sub-options and the
            ``FLOW-MOBILITY`` update notification reason instead. The IANA registry
            is the authority, and it cites :rfc:`8127`.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length == 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_LMAControlledMAGParametersOption(
            type=schema.type,
            length=schema.length + 2,
            suboptions=self._read_lcmp_suboptions(schema.suboptions),
        )
        return data

    def _read_opt_mag_mp(self, schema: 'Schema_MAGMultipathBindingOption', *,
                         options: 'Option') -> 'Data_MAGMultipathBindingOption':
        """Read MH MAG multipath binding option.

        Structure of MH MAG Multipath Binding option [:rfc:`8278#section-4.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |    If-ATT     |    If-Label   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Binding ID   |B|O|             Reserved                      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            :rfc:`8278#section-4.1` makes the ``B`` and ``O`` flags mutually
            exclusive -- neither may be set while the other is -- and reserves
            binding identifiers ``0`` and ``255``.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        bulk = bool(schema.flags['B'])
        overwrite = bool(schema.flags['O'])
        if bulk and overwrite:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_MAGMultipathBindingOption(
            type=schema.type,
            length=schema.length + 2,
            att=schema.att,
            label=schema.label,
            bid=schema.bid,
            bulk=bulk,
            overwrite=overwrite,
        )
        return data

    def _read_opt_mag_id(self, schema: 'Schema_MAGIdentifierOption', *,
                         options: 'Option') -> 'Data_MAGIdentifierOption':
        """Read MH MAG identifier option.

        Structure of MH MAG Identifier option [:rfc:`8278#section-4.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |  Subtype      |  Reserved     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                           Identifier ...                      ~
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The sub-type is borrowed from the *mobile node* identifier subtype
            registry [:rfc:`4283`, :rfc:`8371`], so the identifier's encoding is
            whatever that subtype prescribes. :rfc:`8278` does not restate those
            encodings, so the identifier is kept as :obj:`bytes`.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length < 2:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_MAGIdentifierOption(
            type=schema.type,
            length=schema.length + 2,
            subtype=schema.subtype,
            identifier=schema.identifier,
        )
        return data

    def _read_opt_anchored(self, schema: 'Schema_AnchoredPrefixOption', *,
                           options: 'Option') -> 'Data_AnchoredPrefixOption':
        """Read MH anchored prefix option.

        Structure of MH Anchored Prefix option [:rfc:`8885#section-4.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |   Reserved    | Prefix Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                        Anchored Prefix                        +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 18:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')
        if schema.prefix_length > 128:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_AnchoredPrefixOption(
            type=schema.type,
            length=schema.length + 2,
            prefix_length=schema.prefix_length,
            prefix=schema.prefix,
        )
        return data

    def _read_opt_local_prefix(self, schema: 'Schema_LocalPrefixOption', *,
                               options: 'Option') -> 'Data_LocalPrefixOption':
        """Read MH local prefix option.

        Structure of MH Local Prefix option [:rfc:`8885#section-4.4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |   Reserved    | Prefix Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                         Local Prefix                          +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 18:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')
        if schema.prefix_length > 128:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_LocalPrefixOption(
            type=schema.type,
            length=schema.length + 2,
            prefix_length=schema.prefix_length,
            prefix=schema.prefix,
        )
        return data

    def _read_opt_prev_maar(self, schema: 'Schema_PreviousMAAROption', *,
                            options: 'Option') -> 'Data_PreviousMAAROption':
        """Read MH previous MAAR option.

        Structure of MH Previous MAAR option [:rfc:`8885#section-4.5`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |     Length    |   Reserved    | Prefix Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                     Previous MAAR                             +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                    Home Network Prefix                        +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The prefix length applies to the *home network prefix* only; the
            previous MAAR's own field is a full address
            [:rfc:`8885#section-4.5`].

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 34:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')
        if schema.prefix_length > 128:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_PreviousMAAROption(
            type=schema.type,
            length=schema.length + 2,
            prefix_length=schema.prefix_length,
            maar=schema.maar,
            prefix=schema.prefix,
        )
        return data

    def _read_opt_serv_maar(self, schema: 'Schema_ServingMAAROption', *,
                            options: 'Option') -> 'Data_ServingMAAROption':
        """Read MH serving MAAR option.

        Structure of MH Serving MAAR option [:rfc:`8885#section-4.6`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |      Type     |     Length    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                     S-MAAR's Address                          +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            Unlike the anchored and local prefix options, this one has neither a
            reserved octet nor a prefix length -- it carries a full address and
            nothing else.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 16:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_ServingMAAROption(
            type=schema.type,
            length=schema.length + 2,
            address=schema.address,
        )
        return data

    def _read_opt_dlif_lla(self, schema: 'Schema_DLIFLinkLocalAddressOption', *,
                           options: 'Option') -> 'Data_DLIFLinkLocalAddressOption':
        """Read MH DLIF link-local address option.

        Structure of MH DLIF Link-Local Address option [:rfc:`8885#section-4.7`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |   Type        |    Length     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                  DLIF Link-Local Address                      +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 16:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_DLIFLinkLocalAddressOption(
            type=schema.type,
            length=schema.length + 2,
            address=schema.address,
        )
        return data

    def _read_opt_dlif_lladdr(self, schema: 'Schema_DLIFLinkLayerAddressOption', *,
                              options: 'Option') -> 'Data_DLIFLinkLayerAddressOption':
        """Read MH DLIF link-layer address option.

        Structure of MH DLIF Link-Layer Address option [:rfc:`8885#section-4.8`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type        |    Length     |          Reserved             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                    DLIF Link-Layer Address                    +
           .                              ...                              .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            The address is encoded as in :rfc:`4861#section-4.6.2`, whose width is
            link-type dependent, so no fixed length can be checked here.
            :rfc:`8885#section-4.8` says outright that the option cannot be used on
            links where a link-layer address is unavailable.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length < 2:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_DLIFLinkLayerAddressOption(
            type=schema.type,
            length=schema.length + 2,
            lla=schema.lla,
        )
        return data

    def _read_cga_extensions(self, extensions_schema: 'list[Schema_CGAExtension]') -> 'Extension':
        """Read CGA extensions.

        Structure of CGA extensions [:rfc:`4581`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Extension Type        |   Extension Data Length       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           ~                       Extension Data                          ~
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            extensions_schema: Parsed CGA extensions.

        Returns:
            Parsed CGA extensions data.

        """
        extensions = OrderedMultiDict()  # type: Extension

        for schema in extensions_schema:
            type = schema.type
            name = self._lookup_registry(self.__extension__, type)

            if isinstance(name, str):
                meth_name = f'_read_ext_{name}'
                meth = cast('ExtensionParser',
                            getattr(self, meth_name, self._read_ext_none))
            else:
                meth = name[0]
            data = meth(schema, extensions=extensions)

            # record extension data
            extensions.add(type, data)

        return extensions

    def _read_ext_none(self, schema: 'Schema_UnknownExtension', *,
                       extensions: 'Extension') -> 'Data_UnknownExtension':
        """Read unknown CGA extension.

        Args:
            schema: Parsed extension schema.
            extensions: Parsed MH CGA extensions.

        Returns:
            Constructed extension data.

        """
        data = Data_UnknownExtension(
            type=schema.type,
            length=schema.length + 2,
            data=schema.data,
        )
        return data

    def _read_ext_multiprefix(self, schema: 'Schema_MultiPrefixExtension', *,
                                extensions: 'Extension') -> 'Data_MultiPrefixExtension':
        """Read multi-prefix CGA extension.

        Structure of Multi-Prefix CGA extension [:rfc:`5535`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Extension Type        |   Extension Data Length       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |P|                         Reserved                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                           Prefix[1]                           +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                           Prefix[2]                           +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           .                               .                               .
           .                               .                               .
           .                               .                               .
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                           Prefix[n]                           +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed extension schema.
            extensions: Parsed MH CGA extensions.

        Returns:
            Constructed extension data.

        """
        data = Data_MultiPrefixExtension(
            type=schema.type,
            length=schema.length + 2,
            flag=bool(schema.flags['P']),
            prefixes=tuple(schema.prefixes),
        )
        return data

    def _read_ext_exp(self, schema: 'Schema_ExperimentalExtension', *,
                      extensions: 'Extension') -> 'Data_ExperimentalExtension':
        """Read experimental CGA extension.

        Structure of an experimental CGA extension [:rfc:`4581#section-2`,
        :rfc:`4581#section-3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Extension Type        |   Extension Data Length       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           ~                       Extension Data                          ~
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Note:
            :rfc:`4581#section-3` assigns extension types ``0xFFFD``, ``0xFFFE``
            and ``0xFFFF`` for experimental use as :rfc:`3692` recommends, and
            defines **no** structure for their extension data -- neither it nor
            :rfc:`5535` gives those three a layout, and the IANA registry records
            only their names. So the data is opaque *by specification* here rather
            than merely left undecoded, and no better parse is available to be
            written later. One handler serves all three, since they share a shape
            and differ only in their type code.

        Args:
            schema: Parsed extension schema.
            extensions: Parsed MH CGA extensions.

        Returns:
            Constructed extension data.

        """
        data = Data_ExperimentalExtension(
            type=schema.type,
            length=schema.length + 2,
            data=schema.data,
        )
        return data

    def _make_msg_unknown(self, message: 'Optional[Data_UnknownMessage]' = None, *,
                          data: 'bytes' = b'',
                          **kwargs: 'Any') -> 'Schema_UnknownMessage':
        """Make MH unknown message type.

        Args:
            message: Message data model.
            data: Raw message data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            data = message.data

        return Schema_UnknownMessage(
            data=data,
        )

    def _make_msg_brr(self, message: 'Optional[Data_BindingRefreshRequestMessage]' = None, *,
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_BindingRefreshRequestMessage':
        """Make MH binding refresh request (BRR) message type.

        Args:
            message: Message data model.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            options = message.options
        else:
            options = options or []

        return Schema_BindingRefreshRequestMessage(
            options=self._make_mh_options(options),
        )

    def _make_msg_hoti(self, message: 'Optional[Data_HomeTestInitMessage]' = None, *,
                       cookie: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                       options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                       **kwargs: 'Any') -> 'Schema_HomeTestInitMessage':
        """Make MH home test init (HoTI) message type.

        Args:
            message: Message data model.
            cookie: Home test cookie.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            cookie = message.cookie
            options = message.options
        else:
            options = options or []

        return Schema_HomeTestInitMessage(
            cookie=cookie,
            options=self._make_mh_options(options),
        )

    def _make_msg_coti(self, message: 'Optional[Data_CareofTestInitMessage]' = None, *,
                       cookie: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                       options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                       **kwargs: 'Any') -> 'Schema_CareofTestInitMessage':
        """Make MH care-of test init (CoTI) message type.

        Args:
            message: Message data model.
            cookie: Care-of test cookie.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            cookie = message.cookie
            options = message.options
        else:
            options = options or []

        return Schema_CareofTestInitMessage(
            cookie=cookie,
            options=self._make_mh_options(options),
        )

    def _make_msg_hot(self, message: 'Optional[Data_HomeTestMessage]' = None, *,
                      nonce_index: 'int' = 0,
                      cookie: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                      token: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_HomeTestMessage':
        """Make MH home test (HoT) message type.

        Args:
            message: Message data model.
            nonce_index: Home nonce index.
            cookie: Home test cookie.
            token: Home test token.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            nonce_index = message.nonce_index
            cookie = message.cookie
            token = message.token
            options = message.options
        else:
            options = options or []

        return Schema_HomeTestMessage(
            nonce_index=nonce_index,
            cookie=cookie,
            token=token,
            options=self._make_mh_options(options),
        )

    def _make_msg_cot(self, message: 'Optional[Data_CareofTestMessage]' = None, *,
                      nonce_index: 'int' = 0,
                      cookie: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                      token: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_CareofTestMessage':
        """Make MH care-of test (CoT) message type.

        Args:
            message: Message data model.
            nonce_index: Care-of nonce index.
            cookie: Care-of test cookie.
            token: Care-of test token.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            nonce_index = message.nonce_index
            cookie = message.cookie
            token = message.token
            options = message.options
        else:
            options = options or []

        return Schema_CareofTestMessage(
            nonce_index=nonce_index,
            cookie=cookie,
            token=token,
            options=self._make_mh_options(options),
        )

    def _make_msg_bu(self, message: 'Optional[Data_BindingUpdateMessage]' = None, *,
                     seq: 'int' = 0,
                     ack: 'bool' = False,
                     home: 'bool' = False,
                     lla_compat: 'bool' = False,
                     key_mngt: 'bool' = False,
                     lifetime: 'int | timedelta' = 4,  # reasonable default value
                     options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                     **kwargs: 'Any') -> 'Schema_BindingUpdateMessage':
        """Make MH binding update (BU) message type.

        Args:
            message: Message data model.
            seq: Sequence number.
            ack: Acknowledgement flag.
            home: Home registration flag.
            lla_compat: LLA compatibility flag.
            key_mngt: Key management mobility option flag.
            lifetime: Lifetime in seconds or timedelta.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            seq = message.seq
            ack = message.ack
            home = message.home
            lla_compat = message.lla_compat
            key_mngt = message.key_mngt
            lifetime_val = math.ceil(message.lifetime.total_seconds())
            options = message.options
        else:
            lifetime_val = lifetime if isinstance(lifetime, int) else math.ceil(lifetime.total_seconds())
            options = options or []

        return Schema_BindingUpdateMessage(
            seq=seq,
            flags={
                'A': ack,
                'H': home,
                'L': lla_compat,
                'K': key_mngt,
            },
            lifetime=math.ceil(lifetime_val / 4),
            options=self._make_mh_options(options),
        )

    def _make_msg_ba(self, message: 'Optional[Data_BindingAcknowledgementMessage]' = None, *,
                     status: 'Enum_StatusCode | StdlibEnum | AenumEnum | str | int' = Enum_StatusCode.Binding_Update_accepted_Proxy_Binding_Update_accepted,
                     status_default: 'Optional[int]' = None,
                     status_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                     status_reversed: 'bool' = False,
                     key_mngt: 'bool' = False,
                     seq: 'int' = 0,
                     lifetime: 'int | timedelta' = 4,  # reasonable default value
                     options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                     **kwargs: 'Any') -> 'Schema_BindingAcknowledgementMessage':
        """Make MH binding acknowledge (BA) message type.

        Args:
            message: Message data model.
            status: Status code.
            status_default: Default status code.
            status_namespace: Status code namespace.
            status_reversed: Reverse status code namespace.
            key_mngt: Key management mobility option flag.
            seq: Sequence number.
            lifetime: Lifetime in seconds or timedelta.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            status_val = message.status
            key_mngt = message.key_mngt
            seq = message.seq
            lifetime_val = math.ceil(message.lifetime.total_seconds())
            options = message.options
        else:
            status_val = self._make_index(status, status_default, namespace=status_namespace,  # type: ignore[assignment]
                                          reversed=status_reversed, pack=False)
            lifetime_val = lifetime if isinstance(lifetime, int) else math.ceil(lifetime.total_seconds())
            options = options or []

        return Schema_BindingAcknowledgementMessage(
            status=status_val,
            flags={
                'K': key_mngt,
            },
            seq=seq,
            lifetime=math.ceil(lifetime_val / 4),
            options=self._make_mh_options(options),
        )

    def _make_msg_be(self, message: 'Optional[Data_BindingErrorMessage]' = None, *,
                     status: 'Enum_StatusCode | StdlibEnum | AenumEnum | str | int' = Enum_StatusCode.Binding_Update_accepted_Proxy_Binding_Update_accepted,
                     status_default: 'Optional[int]' = None,
                     status_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                     status_reversed: 'bool' = False,
                     home: 'IPv6Address | int | str | bytes' = '::',
                     options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                     **kwargs: 'Any') -> 'Schema_BindingErrorMessage':
        """Make MH binding error (BE) message type.

        Args:
            message: Message data model.
            status: Status code.
            status_default: Default status code.
            status_namespace: Status code namespace.
            status_reversed: Reverse status code namespace.
            home: Home address.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            status_val = message.status
            home = message.home
            options = message.options
        else:
            status_val = self._make_index(status, status_default, namespace=status_namespace,  # type: ignore[assignment]
                                          reversed=status_reversed, pack=False)
            options = options or []

        return Schema_BindingErrorMessage(
            status=status_val,
            home=home,
            options=self._make_mh_options(options),
        )

    def _make_msg_fbu(self, message: 'Optional[Data_FastBindingUpdateMessage]' = None, *,
                      seq: 'int' = 0,
                      ack: 'bool' = True,  # MUST be set, c.f., RFC 5568, section 6.2.2
                      home: 'bool' = True,  # MUST be set, c.f., RFC 5568, section 6.2.2
                      lla_compat: 'bool' = False,
                      key_mngt: 'bool' = False,
                      lifetime: 'int | timedelta' = 4,  # reasonable default value
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_FastBindingUpdateMessage':
        """Make MH fast binding update (FBU) message type.

        Args:
            message: Message data model.
            seq: Sequence number.
            ack: Acknowledgement flag.
            home: Home registration flag.
            lla_compat: LLA compatibility flag.
            key_mngt: Key management mobility option flag.
            lifetime: Lifetime in seconds or timedelta.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            seq = message.seq
            ack = message.ack
            home = message.home
            lla_compat = message.lla_compat
            key_mngt = message.key_mngt
            lifetime_val = math.ceil(message.lifetime.total_seconds())
            options = message.options
        else:
            lifetime_val = lifetime if isinstance(lifetime, int) else math.ceil(lifetime.total_seconds())
            options = options or []

        return Schema_FastBindingUpdateMessage(
            seq=seq,
            flags={
                'A': ack,
                'H': home,
                'L': lla_compat,
                'K': key_mngt,
            },
            lifetime=math.ceil(lifetime_val / 4),
            options=self._make_mh_options(options),
        )

    def _make_msg_fback(self, message: 'Optional[Data_FastBindingAcknowledgmentMessage]' = None, *,
                        status: 'FastBindingAcknowledgmentStatus | StdlibEnum | AenumEnum | str | int' = FastBindingAcknowledgmentStatus.Fast_Binding_Update_accepted,
                        status_default: 'Optional[int]' = None,
                        status_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                        status_reversed: 'bool' = False,
                        key_mngt: 'bool' = False,
                        seq: 'int' = 0,
                        lifetime: 'int | timedelta' = 4,  # reasonable default value
                        options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                        **kwargs: 'Any') -> 'Schema_FastBindingAcknowledgmentMessage':
        """Make MH fast binding acknowledgment (FBack) message type.

        Args:
            message: Message data model.
            status: Status code, c.f.,
                :class:`~pcapkit.protocols.internet.mh.FastBindingAcknowledgmentStatus`.
            status_default: Default status code.
            status_namespace: Status code namespace.
            status_reversed: Reverse status code namespace.
            key_mngt: Key management mobility option flag.
            seq: Sequence number.
            lifetime: Lifetime in seconds or timedelta.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            status_val = message.status
            key_mngt = message.key_mngt
            seq = message.seq
            lifetime_val = math.ceil(message.lifetime.total_seconds())
            options = message.options
        else:
            status_val = self._make_index(status, status_default, namespace=status_namespace,  # type: ignore[assignment]
                                          reversed=status_reversed, pack=False)
            lifetime_val = lifetime if isinstance(lifetime, int) else math.ceil(lifetime.total_seconds())
            options = options or []

        return Schema_FastBindingAcknowledgmentMessage(
            status=status_val,
            flags={
                'K': key_mngt,
            },
            seq=seq,
            lifetime=math.ceil(lifetime_val / 4),
            options=self._make_mh_options(options),
        )

    def _make_msg_fna(self, message: 'Optional[Data_FastNeighborAdvertisementMessage]' = None, *,
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_FastNeighborAdvertisementMessage':
        """Make MH fast neighbor advertisement (FNA) message type.

        Args:
            message: Message data model.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            options = message.options
        else:
            options = options or []

        return Schema_FastNeighborAdvertisementMessage(
            options=self._make_mh_options(options),
        )

    def _make_msg_emh(self, message: 'Optional[Data_ExperimentalMessage]' = None, *,
                      data: 'bytes' = b'\x00\x00',  # 2 bytes of padding, c.f., RFC 5096, section 3
                      **kwargs: 'Any') -> 'Schema_ExperimentalMessage':
        """Make MH experimental mobility header message type.

        Args:
            message: Message data model.
            data: Experimental message data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            data = message.data

        return Schema_ExperimentalMessage(
            data=data,
        )

    def _make_msg_hi(self, message: 'Optional[Data_HandoverInitiateMessage]' = None, *,
                     seq: 'int' = 0,
                     assign: 'bool' = False,
                     buffer: 'bool' = False,
                     proxy: 'bool' = False,
                     forward: 'bool' = False,
                     code: 'Enum_HandoverInitiateStatus | StdlibEnum | AenumEnum | str | int' = Enum_HandoverInitiateStatus.FBU_with_the_PCoA_as_source_IP_address,
                     code_default: 'Optional[int]' = None,
                     code_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                     code_reversed: 'bool' = False,
                     options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                     **kwargs: 'Any') -> 'Schema_HandoverInitiateMessage':
        """Make MH handover initiate (HI) message type.

        Args:
            message: Message data model.
            seq: Sequence number.
            assign: Assigned address configuration flag.
            buffer: Buffer flag.
            proxy: Proxy flag.
            forward: Forwarding flag.
            code: Code.
            code_default: Default code.
            code_namespace: Code namespace.
            code_reversed: Reverse code namespace.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            seq = message.seq
            assign = message.assign
            buffer = message.buffer
            proxy = message.proxy
            forward = message.forward
            code_val = message.code
            options = message.options
        else:
            code_val = self._make_index(code, code_default, namespace=code_namespace,  # type: ignore[assignment]
                                        reversed=code_reversed, pack=False)
            options = options or []

        return Schema_HandoverInitiateMessage(
            seq=seq,
            flags={
                'S': assign,
                'U': buffer,
                'P': proxy,
                'F': forward,
            },
            code=code_val,
            options=self._make_mh_options(options),
        )

    def _make_msg_hack(self, message: 'Optional[Data_HandoverAcknowledgeMessage]' = None, *,
                       seq: 'int' = 0,
                       buffer: 'bool' = False,
                       proxy: 'bool' = False,
                       forward: 'bool' = False,
                       code: 'Enum_HandoverACKStatus | StdlibEnum | AenumEnum | str | int' = Enum_HandoverACKStatus.Handover_Accepted_with_NCoA_valid,
                       code_default: 'Optional[int]' = None,
                       code_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                       code_reversed: 'bool' = False,
                       options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                       **kwargs: 'Any') -> 'Schema_HandoverAcknowledgeMessage':
        """Make MH handover acknowledge (HAck) message type.

        Args:
            message: Message data model.
            seq: Sequence number.
            buffer: Buffer flag.
            proxy: Proxy flag.
            forward: Forwarding flag.
            code: Code.
            code_default: Default code.
            code_namespace: Code namespace.
            code_reversed: Reverse code namespace.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            seq = message.seq
            buffer = message.buffer
            proxy = message.proxy
            forward = message.forward
            code_val = message.code
            options = message.options
        else:
            code_val = self._make_index(code, code_default, namespace=code_namespace,  # type: ignore[assignment]
                                        reversed=code_reversed, pack=False)
            options = options or []

        return Schema_HandoverAcknowledgeMessage(
            seq=seq,
            flags={
                'U': buffer,
                'P': proxy,
                'F': forward,
            },
            code=code_val,
            options=self._make_mh_options(options),
        )

    def _make_msg_has(self, message: 'Optional[Data_HomeAgentSwitchMessage]' = None, *,
                      addresses: 'Optional[list[IPv6Address | bytes | str | int]]' = None,
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_HomeAgentSwitchMessage':
        """Make MH home agent switch (HAS) message type.

        Args:
            message: Message data model.
            addresses: Alternate home agent addresses. An empty list is valid and
                asks the mobile node to run home agent discovery.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            addresses = cast('list[IPv6Address | bytes | str | int]', list(message.addresses))
            options = message.options
        else:
            addresses = addresses or []
            options = options or []

        return Schema_HomeAgentSwitchMessage(
            count=len(addresses),
            addresses=addresses,
            options=self._make_mh_options(options),
        )

    def _make_msg_hb(self, message: 'Optional[Data_HeartbeatMessage]' = None, *,
                     unsolicited: 'bool' = False,
                     response: 'bool' = False,
                     seq: 'int' = 0,
                     options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                     **kwargs: 'Any') -> 'Schema_HeartbeatMessage':
        """Make MH heartbeat message type.

        Args:
            message: Message data model.
            unsolicited: Unsolicited flag.
            response: Response flag; unset makes this a heartbeat request.
            seq: Sequence number.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            unsolicited = message.unsolicited
            response = message.response
            seq = message.seq
            options = message.options
        else:
            options = options or []

        return Schema_HeartbeatMessage(
            flags={
                'U': unsolicited,
                'R': response,
            },
            seq=seq,
            options=self._make_mh_options(options),
        )

    def _make_msg_brm(self, message: 'Optional[Data_BindingRevocationMessage]' = None, *,
                      br_type: 'Enum_BindingRevocation | StdlibEnum | AenumEnum | str | int' = Enum_BindingRevocation.Binding_Revocation_Indication,
                      br_type_default: 'Optional[int]' = None,
                      br_type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      br_type_reversed: 'bool' = False,
                      code: 'Enum_RevocationTrigger | Enum_RevocationStatusCode | StdlibEnum | AenumEnum | str | int' = Enum_RevocationTrigger.Unspecified,
                      code_default: 'Optional[int]' = None,
                      code_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      code_reversed: 'bool' = False,
                      seq: 'int' = 0,
                      proxy: 'bool' = False,
                      ipv4_hoa: 'bool' = False,
                      global_revocation: 'bool' = False,
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_BindingRevocationMessage':
        """Make MH binding revocation (BRM) message type.

        Args:
            message: Message data model.
            br_type: Binding revocation type, saying which form of the message
                this is.
            br_type_default: Default binding revocation type.
            br_type_namespace: Binding revocation type namespace.
            br_type_reversed: Reverse binding revocation type namespace.
            code: Revocation trigger, for an indication, or acknowledgement
                status, for an acknowledgement.
            code_default: Default code.
            code_namespace: Code namespace.
            code_reversed: Reverse code namespace.
            seq: Sequence number.
            proxy: Proxy binding flag.
            ipv4_hoa: IPv4 home address binding only flag.
            global_revocation: Global revocation flag.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            br_type_val = message.br_type  # type: Enum_BindingRevocation
            code_val = message.code  # type: Enum_RevocationTrigger | Enum_RevocationStatusCode
            seq = message.seq
            proxy = message.proxy
            ipv4_hoa = message.ipv4_hoa
            global_revocation = message.global_revocation
            options = message.options
        else:
            br_type_val = self._make_index(br_type, br_type_default, namespace=br_type_namespace,  # type: ignore[assignment]
                                           reversed=br_type_reversed, pack=False)
            code_val = self._make_index(code, code_default, namespace=code_namespace,  # type: ignore[assignment]
                                        reversed=code_reversed, pack=False)
            options = options or []

        return Schema_BindingRevocationMessage(
            br_type=br_type_val,
            code=code_val,
            seq=seq,
            flags={
                'P': proxy,
                'V': ipv4_hoa,
                'G': global_revocation,
            },
            options=self._make_mh_options(options),
        )

    def _make_msg_lri(self, message: 'Optional[Data_LocalizedRoutingInitiationMessage]' = None, *,
                      seq: 'int' = 0,
                      lifetime: 'int | timedelta' = 0,
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_LocalizedRoutingInitiationMessage':
        """Make MH localized routing initiation (LRI) message type.

        Args:
            message: Message data model.
            seq: Sequence number.
            lifetime: Lifetime, in seconds or as a
                :class:`~datetime.timedelta`. Unlike the binding messages, this
                one counts seconds rather than units of 4 seconds, so the value is
                not scaled.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            seq = message.seq
            lifetime_val = math.ceil(message.lifetime.total_seconds())
            options = message.options
        else:
            lifetime_val = lifetime if isinstance(lifetime, int) else math.ceil(lifetime.total_seconds())
            options = options or []

        return Schema_LocalizedRoutingInitiationMessage(
            seq=seq,
            lifetime=lifetime_val,
            options=self._make_mh_options(options),
        )

    def _make_msg_lra(self, message: 'Optional[Data_LocalizedRoutingAcknowledgmentMessage]' = None, *,
                      seq: 'int' = 0,
                      unsolicited: 'bool' = False,
                      status: 'LocalizedRoutingStatus | StdlibEnum | AenumEnum | str | int' = LocalizedRoutingStatus.Success,
                      status_default: 'Optional[int]' = None,
                      status_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      status_reversed: 'bool' = False,
                      lifetime: 'int | timedelta' = 0,
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_LocalizedRoutingAcknowledgmentMessage':
        """Make MH localized routing acknowledgment (LRA) message type.

        Args:
            message: Message data model.
            seq: Sequence number.
            unsolicited: Unsolicited flag.
            status: Status, c.f.,
                :class:`~pcapkit.protocols.internet.mh.LocalizedRoutingStatus`.
            status_default: Default status.
            status_namespace: Status namespace.
            status_reversed: Reverse status namespace.
            lifetime: Lifetime, in seconds or as a
                :class:`~datetime.timedelta`.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            seq = message.seq
            unsolicited = message.unsolicited
            status_val = message.status  # type: int
            lifetime_val = math.ceil(message.lifetime.total_seconds())
            options = message.options
        else:
            status_val = self._make_index(status, status_default, namespace=status_namespace,
                                          reversed=status_reversed, pack=False)
            lifetime_val = lifetime if isinstance(lifetime, int) else math.ceil(lifetime.total_seconds())
            options = options or []

        return Schema_LocalizedRoutingAcknowledgmentMessage(
            seq=seq,
            flags={
                'U': unsolicited,
            },
            status=status_val,
            lifetime=lifetime_val,
            options=self._make_mh_options(options),
        )

    def _make_msg_upn(self, message: 'Optional[Data_UpdateNotificationMessage]' = None, *,
                      seq: 'int' = 0,
                      reason: 'Enum_UpdateNotificationReason | StdlibEnum | AenumEnum | str | int' = Enum_UpdateNotificationReason.FORCE_REREGISTRATION,
                      reason_default: 'Optional[int]' = None,
                      reason_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      reason_reversed: 'bool' = False,
                      ack: 'bool' = False,
                      retransmit: 'bool' = False,
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_UpdateNotificationMessage':
        """Make MH update notification (UPN) message type.

        Args:
            message: Message data model.
            seq: Sequence number.
            reason: Notification reason.
            reason_default: Default notification reason.
            reason_namespace: Notification reason namespace.
            reason_reversed: Reverse notification reason namespace.
            ack: Acknowledgement requested flag.
            retransmit: Retransmission flag.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            seq = message.seq
            reason_val = message.reason  # type: Enum_UpdateNotificationReason
            ack = message.ack
            retransmit = message.retransmit
            options = message.options
        else:
            reason_val = self._make_index(reason, reason_default, namespace=reason_namespace,  # type: ignore[assignment]
                                          reversed=reason_reversed, pack=False)
            options = options or []

        return Schema_UpdateNotificationMessage(
            seq=seq,
            reason=reason_val,
            flags={
                'A': ack,
                'D': retransmit,
            },
            options=self._make_mh_options(options),
        )

    def _make_msg_upa(self, message: 'Optional[Data_UpdateNotificationAcknowledgementMessage]' = None, *,
                      seq: 'int' = 0,
                      status: 'Enum_UpdateNotificationACKStatus | StdlibEnum | AenumEnum | str | int' = Enum_UpdateNotificationACKStatus.SUCCESS,
                      status_default: 'Optional[int]' = None,
                      status_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      status_reversed: 'bool' = False,
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_UpdateNotificationAcknowledgementMessage':
        """Make MH update notification acknowledgement (UPA) message type.

        Args:
            message: Message data model.
            seq: Sequence number.
            status: Status.
            status_default: Default status.
            status_namespace: Status namespace.
            status_reversed: Reverse status namespace.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            seq = message.seq
            status_val = message.status  # type: Enum_UpdateNotificationACKStatus
            options = message.options
        else:
            status_val = self._make_index(status, status_default, namespace=status_namespace,  # type: ignore[assignment]
                                          reversed=status_reversed, pack=False)
            options = options or []

        return Schema_UpdateNotificationAcknowledgementMessage(
            seq=seq,
            status=status_val,
            options=self._make_mh_options(options),
        )

    def _make_msg_fbm(self, message: 'Optional[Data_FlowBindingMessage]' = None, *,
                      fb_type: 'Enum_FlowBindingType | StdlibEnum | AenumEnum | str | int' = Enum_FlowBindingType.Indication,
                      fb_type_default: 'Optional[int]' = None,
                      fb_type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      fb_type_reversed: 'bool' = False,
                      seq: 'int' = 0,
                      code: 'Enum_FlowBindingIndicationTrigger | Enum_FlowBindingACKStatus | StdlibEnum | AenumEnum | str | int' = Enum_FlowBindingIndicationTrigger.Unspecified,
                      code_default: 'Optional[int]' = None,
                      code_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      code_reversed: 'bool' = False,
                      ack: 'bool' = False,
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_FlowBindingMessage':
        """Make MH flow binding (FB) message type.

        Args:
            message: Message data model.
            fb_type: Flow binding type, saying which form of the message this is.
            fb_type_default: Default flow binding type.
            fb_type_namespace: Flow binding type namespace.
            fb_type_reversed: Reverse flow binding type namespace.
            seq: Sequence number.
            code: Indication trigger, for an indication, or acknowledgement
                status, for an acknowledgement.
            code_default: Default code.
            code_namespace: Code namespace.
            code_reversed: Reverse code namespace.
            ack: Acknowledgement requested flag. Meaningful only in an
                indication.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            fb_type_val = message.fb_type  # type: Enum_FlowBindingType
            seq = message.seq
            code_val = message.code  # type: Enum_FlowBindingIndicationTrigger | Enum_FlowBindingACKStatus
            ack = message.ack
            options = message.options
        else:
            fb_type_val = self._make_index(fb_type, fb_type_default, namespace=fb_type_namespace,  # type: ignore[assignment]
                                           reversed=fb_type_reversed, pack=False)
            code_val = self._make_index(code, code_default, namespace=code_namespace,  # type: ignore[assignment]
                                        reversed=code_reversed, pack=False)
            options = options or []

        return Schema_FlowBindingMessage(
            fb_type=fb_type_val,
            seq=seq,
            code=code_val,
            flags={
                'A': ack,
            },
            options=self._make_mh_options(options),
        )

    def _make_msg_sq(self, message: 'Optional[Data_SubscriptionQueryMessage]' = None, *,
                     seq: 'int' = 0,
                     options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                     **kwargs: 'Any') -> 'Schema_SubscriptionQueryMessage':
        """Make MH subscription query (SQ) message type.

        Args:
            message: Message data model.
            seq: Sequence number, counted modulo 256.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            seq = message.seq
            options = message.options
        else:
            options = options or []

        return Schema_SubscriptionQueryMessage(
            seq=seq,
            options=self._make_mh_options(options),
        )

    def _make_msg_sr(self, message: 'Optional[Data_SubscriptionResponseMessage]' = None, *,
                     seq: 'int' = 0,
                     info: 'bool' = False,
                     options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                     **kwargs: 'Any') -> 'Schema_SubscriptionResponseMessage':
        """Make MH subscription response (SR) message type.

        Args:
            message: Message data model.
            seq: Sequence number, echoed from the query.
            info: Multicast information flag.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            seq = message.seq
            info = message.info
            options = message.options
        else:
            options = options or []

        return Schema_SubscriptionResponseMessage(
            seq=seq,
            flags={
                'I': info,
            },
            options=self._make_mh_options(options),
        )

    def _make_pad_options(self, offset: 'int') -> 'tuple[list[Schema_PadOption], int]':
        """Make the padding options needed to align the header to 8 octets.

        Args:
            offset: Number of octets emitted so far, **counting the six octets
                of the fixed header** (``Payload Proto``, ``Header Len``,
                ``MH Type``, ``Reserved`` and ``Checksum``) as well as the whole
                message data.

        Returns:
            Tuple of the padding option schemas and the number of octets they
            occupy.

        Note:
            The Mobility Header is a multiple of 8 octets and
            :attr:`~pcapkit.protocols.schema.internet.mh.MH.length` counts those
            units less one [:rfc:`6275#section-6.1.1`]. Its fixed part is
            **six** octets, not the two of an IPv6 options header, so it is
            ``len(data) + 6`` that has to be aligned -- which means the message
            data is well formed only when it is 2 octets past a multiple of 8,
            a different modulus from the one the extension headers use.

            A ``PadN`` option spends two octets on its own type and
            ``Option Length`` fields before any padding data, so occupying
            ``pad_len`` octets means an ``Option Length`` of ``pad_len - 2``.
            One or two octets are padded with ``Pad1`` options instead, that
            being the only form which can occupy a single octet
            [:rfc:`6275#section-6.2.5`]; two octets need two separate ``Pad1``
            schemas, since a schema instance is mutable and must not be shared
            between two entries of the option list.

        """
        if offset % 8 == 0:
            return [], 0

        pad_len = 8 - (offset % 8)
        if pad_len <= 2:
            return [self._make_opt_pad(Enum_Option.Pad1, length=0)  # type: ignore[arg-type]
                    for _ in range(pad_len)], pad_len
        return [self._make_opt_pad(Enum_Option.PadN, length=pad_len - 2)], pad_len  # type: ignore[arg-type]

    def _pad_mh_message(self, data: 'Schema_Packet | bytes') -> 'Schema_Packet | bytes':
        """Pad an MH message so that the Mobility Header aligns to 8 octets.

        Args:
            data: Constructed message data.

        Returns:
            The message data, with padding options appended if any were needed.

        Note:
            The padding goes into the message's mobility options, which is where
            :rfc:`6275#section-6.2.5` puts it. A message whose body is opaque has
            nowhere to put it --
            :class:`~pcapkit.protocols.schema.internet.mh.UnknownMessage` and
            :class:`~pcapkit.protocols.schema.internet.mh.ExperimentalMessage`
            carry raw bytes and no options, as does a ``data`` argument given
            directly as :obj:`bytes` -- so for those the padding is appended to the
            message body itself and a
            :class:`~pcapkit.utilities.warnings.ProtocolWarning` says so.

            Appending is necessary rather than optional: ``length`` is
            ``(len(data) + 6) // 8 - 1``, which floors, so leaving an opaque body
            short emitted 10, 12 or 14 octets while declaring 8, and a parser reads
            8 and misinterprets the remainder. Since the caller asked for a packet
            to be built and the shortfall is recoverable, completing it beats
            refusing -- the warning is there because the emitted body is then not
            byte-for-byte what was handed in.

        """
        pad_opts, pad_len = self._make_pad_options(len(data) + 6)
        if pad_len == 0:
            return data

        options = getattr(data, 'options', None)
        # NOTE: The ``isinstance`` test comes first so that the type checker can
        # narrow ``data`` for the assignment below; at runtime ``getattr`` has
        # already covered the :obj:`bytes` case by returning :obj:`None`.
        if isinstance(data, bytes) or options is None:
            warn(f'{self.alias}: message data of {len(data)} octets carries no '
                 f'mobility options to hold padding, so {pad_len} octet(s) were '
                 'appended to the message body to align the header',
                 ProtocolWarning)
            if isinstance(data, bytes):
                return data + b'\x00' * pad_len

            # An opaque schema body -- UnknownMessage, ExperimentalMessage -- keeps
            # its content in ``data`` rather than in options, so that is where the
            # octets go. Rebound rather than mutated in place so that ``len()`` and
            # ``pack()`` see the change, exactly as for the options branch below.
            body = getattr(data, 'data', None)
            if not isinstance(body, bytes):
                raise ProtocolError(
                    f'{self.alias}: message data of {len(data)} octets needs '
                    f'{pad_len} octet(s) of padding, but the body is neither bytes '
                    'nor a schema carrying bytes, so there is nowhere to put it')
            data.data = body + b'\x00' * pad_len
            return data

        # NOTE: Rebinding the attribute rather than mutating the list in place is
        # what marks the schema as updated, so that ``len()`` and ``pack()`` take
        # the padding into account.
        data.options = list(options) + pad_opts
        return data

    def _make_mh_options(self, options: 'Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]') -> 'list[Schema_Option | bytes]':
        """Make options for MH.

        Args:
            options: MH options.

        Returns:
            Mobility options list.

        """
        if isinstance(options, list):
            options_list = []  # type: list[Schema_Option | bytes]
            for schema in options:
                if isinstance(schema, bytes):
                    code = Enum_Option.get(int.from_bytes(schema[0:1], 'big', signed=False))

                    data = schema  # type: Schema_Option | bytes
                elif isinstance(schema, Schema):
                    data = schema
                else:
                    code, args = cast('tuple[Enum_Option, dict[str, Any]]', schema)
                    name = self._lookup_registry(self.__option__, code)
                    if isinstance(name, str):
                        meth_name = f'_make_opt_{name}'
                        meth = cast('OptionConstructor',
                                    getattr(self, meth_name, self._make_opt_none))
                    else:
                        meth = name[1]
                    data = meth(code, **args)

                options_list.append(data)
            return options_list

        options_list = []
        for code, option in options.items(multi=True):
            name = self._lookup_registry(self.__option__, code)
            if isinstance(name, str):
                meth_name = f'_make_opt_{name}'
                meth = cast('OptionConstructor',
                            getattr(self, meth_name, self._make_opt_none))
            else:
                meth = name[1]

            data = meth(code, option)
            options_list.append(data)
        return options_list

    def _make_opt_none(self, type: 'Enum_Option', option: 'Optional[Data_UnassignedOption]' = None, *,
                             data: 'bytes' = b'',
                             **kwargs: 'Any') -> 'Schema_UnassignedOption':
        """Make MH unassigned option.

        Args:
            type: Option type.
            option: Option data model.
            data: Option data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            data = option.data

        return Schema_UnassignedOption(
            type=type,
            length=len(data),
            data=data,
        )

    def _make_opt_pad(self, type: 'Enum_Option', option: 'Optional[Data_PadOption]' = None, *,
                      length: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_PadOption':
        """Make MH pad option.

        Args:
            type: Option type.
            option: Option data model.
            length: Value of the ``Option Length`` field, i.e. the number of
                padding octets *after* the two octets of the option header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Note:
            :attr:`Data_PadOption.length
            <pcapkit.protocols.data.internet.mh.PadOption.length>` counts the
            *whole* option, whereas :attr:`Schema_PadOption.length
            <pcapkit.protocols.schema.internet.mh.PadOption.length>` is the
            ``Option Length`` field -- two octets fewer, and absent altogether
            for a ``Pad1``. Copying one into the other unconverted is why
            re-making a parsed ``PadN`` used to come back two octets too long.

        """
        if option is not None:
            length = 0 if option.type == Enum_Option.Pad1 else option.length - 2

        if type == Enum_Option.Pad1 and length != 0:
            # raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid format')
            warn(f'{self.alias}: [OptNo {type}] invalid format', ProtocolWarning)
            type = Enum_Option.PadN  # type: ignore[assignment]
        if type == Enum_Option.PadN and length == 0:
            # raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid format')
            warn(f'{self.alias}: [OptNo {type}] invalid format', ProtocolWarning)
            type = Enum_Option.Pad1  # type: ignore[assignment]

        return Schema_PadOption(
            type=type,
            length=length,
        )

    def _make_opt_bra(self, type: 'Enum_Option', option: 'Optional[Data_BindingRefreshAdviceOption]' = None, *,
                      interval: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_BindingRefreshAdviceOption':
        """Make MH binding refresh advice option.

        Args:
            type: Option type.
            option: Option data model.
            interval: Refresh interval.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            interval = option.interval

        return Schema_BindingRefreshAdviceOption(
            type=type,
            length=2,
            interval=interval,
        )

    def _make_opt_aca(self, type: 'Enum_Option', option: 'Optional[Data_AlternateCareofAddressOption]' = None, *,
                      address: 'bytes | str | int | IPv6Address' = '::',
                      **kwargs: 'Any') -> 'Schema_AlternateCareofAddressOption':
        """Make MH alternate care-of address option.

        Args:
            type: Option type.
            option: Option data model.
            address: Alternate care-of address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            address = option.address

        return Schema_AlternateCareofAddressOption(
            type=type,
            length=16,
            address=address,
        )

    def _make_opt_ni(self, type: 'Enum_Option', option: 'Optional[Data_NonceIndicesOption]' = None, *,
                     home: 'int' = 0,
                     careof: 'int' = 0,
                     **kwargs: 'Any') -> 'Schema_NonceIndicesOption':
        """Make MH nonce indices option.

        Args:
            type: Option type.
            option: Option data model.
            home: Home nonce index.
            careof: Care-of nonce index.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            home = option.home
            careof = option.careof

        return Schema_NonceIndicesOption(
            type=type,
            length=4,
            home=home,
            careof=careof,
        )

    def _make_opt_bad(self, type: 'Enum_Option', option: 'Optional[Data_AuthorizationDataOption]' = None, *,
                      data: 'bytes' = b'',
                      **kwargs: 'Any') -> 'Schema_AuthorizationDataOption':
        """Make MH binding authorization data option.

        Args:
            type: Option type.
            option: Option data model.
            data: Authenticator.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            data = option.data

        if len(data) % 8 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid format')

        return Schema_AuthorizationDataOption(
            type=type,
            length=len(data),
            data=data,
        )

    def _make_opt_mnp(self, type: 'Enum_Option', option: 'Optional[Data_MobileNetworkPrefixOption]' = None, *,
                      prefix: 'bytes | str | IPv6Network' = '::/0',
                      **kwargs: 'Any') -> 'Schema_MobileNetworkPrefixOption':
        """Make MH mobile network prefix option.

        Args:
            type: Option type.
            option: Option data model.
            prefix: Mobile network prefix.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            prefix = option.prefix

        prefix_val = ipaddress.ip_network(prefix)
        if prefix_val.version != 6:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid movile network prefix: {prefix!r}')
        prefix_length = prefix_val.prefixlen
        prefix_addr = prefix_val.network_address

        return Schema_MobileNetworkPrefixOption(
            type=type,
            length=18,
            prefix_length=prefix_length,
            prefix=prefix_addr,
        )

    def _make_opt_lla(self, type: 'Enum_Option', option: 'Optional[Data_LinkLayerAddressOption]' = None, *,
                      address: 'bytes' = b'',
                      **kwargs: 'Any') -> 'Schema_LinkLayerAddressOption':
        """Make MH link-layer address option.

        Args:
            type: Option type.
            option: Option data model.
            address: Link-layer address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            address = option.lla

        return Schema_LinkLayerAddressOption(
            type=type,
            length=len(address) + 1,
            code=Enum_LLACode.MH,  # type: ignore[arg-type]
            lla=address,
        )

    def _make_opt_mn_id(self, type: 'Enum_Option', option: 'Optional[Data_MNIDOption]' = None, *,
                       subtype: 'Enum_MNIDSubtype | StdlibEnum | AenumEnum | str | int' = Enum_MNIDSubtype.IPv6_Address,
                       subtype_default: 'Optional[int]' = None,
                       subtype_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                       subtype_reversed: 'bool' = False,
                       identifier: 'bytes | str | IPv6Address | int' = '::',
                       **kwargs: 'Any') -> 'Schema_MNIDOption':
        """Make MH mobile node identifier option.

        Args:
            type: Option type.
            option: Option data model.
            subtype: MN-ID subtype.
            subtype_default: MN-ID subtype default value.
            subtype_namespace: MN-ID subtype namespace.
            subtype_reversed: MN-ID subtype reversed flag.
            identifier: Identifier. An :obj:`int` remains accepted for the
                ``IPv6_Address`` subtype (converted the same way as any other
                value :class:`ipaddress.IPv6Address` accepts), but is rejected
                for every other subtype: their fields are variable-length --
                :obj:`str` for ``NAI``, :obj:`bytes` for the rest -- sized from
                the wire ``length`` rather than from anything ``subtype`` fixes
                on its own, so there is no non-arbitrary width to convert an
                :obj:`int` into (c.f. #467).
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``identifier`` is an :obj:`int` and ``subtype``
                is not ``IPv6_Address``.

        """
        if option is not None:
            subtype_val = option.subtype
            identifier = option.identifier
        else:
            subtype_val = self._make_index(subtype, subtype_default, namespace=subtype_namespace,  # type: ignore[assignment]
                                           reversed=subtype_reversed, pack=False)

        # NOTE: The wire format is chosen by ``subtype_val`` (c.f. ``mn_id_selector``),
        # not by the Python type of ``identifier``, so the width has to be taken from
        # the former. For the ``IPv6_Address`` subtype the schema always packs a fixed
        # 16-octet address (:class:`~pcapkit.corekit.fields.ipaddress.IPv6AddressField`
        # ignores any declared length), so ``identifier`` is normalised to that wire
        # form here as well, keeping the packed bytes and the declared length derived
        # from one value instead of two independent computations (c.f. #448).
        if subtype_val == Enum_MNIDSubtype.IPv6_Address:
            if not isinstance(identifier, ipaddress.IPv6Address):
                identifier = ipaddress.IPv6Address(identifier)
            id_len = 16
        elif isinstance(identifier, int):
            # NOTE: Every other subtype's field is inherently variable-length in
            # the schema (c.f. ``mn_id_selector``): a
            # :class:`~pcapkit.corekit.fields.strings.StringField` for ``NAI``, a
            # :class:`~pcapkit.corekit.fields.strings.BytesField` for the rest --
            # both sized from the packed ``length`` header, not from anything
            # ``subtype_val`` fixes on its own. That is unlike ``IPv6_Address``,
            # whose 16-octet width is a spec-fixed constant independent of the
            # identifier's value. Neither field type converts an ``int`` --
            # ``BytesField`` packs the value as-is and ``StringField`` calls
            # ``.encode()`` on it -- so there is no non-arbitrary width to take
            # from ``subtype_val`` here: picking one (e.g. from the int's own
            # ``bit_length()``, as this branch used to) would just reintroduce
            # the type-vs-subtype confusion that produced this defect, only
            # without the crash (c.f. #467). Reject instead of silently
            # accepting a value that cannot pack.
            expected = 'str' if subtype_val == Enum_MNIDSubtype.NAI else 'bytes'
            raise ProtocolError(f'{self.alias}: [OptNo {type}] MN-ID subtype '
                                f'{Enum_MNIDSubtype(subtype_val)!r} identifier must be '
                                f'{expected}, not int')
        else:
            id_len = len(identifier)

        return Schema_MNIDOption(
            type=type,
            length=1 + id_len,
            subtype=subtype_val,
            identifier=identifier,
        )

    def _make_opt_auth(self, type: 'Enum_Option', option: 'Optional[Data_AuthOption]' = None, *,
                       subtype: 'Enum_AuthSubtype | StdlibEnum | AenumEnum | str | int' = Enum_AuthSubtype.MN_HA,
                       subtype_default: 'Optional[int]' = None,
                       subtype_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                       subtype_reversed: 'bool' = False,
                       spi: 'int' = 0,
                       data: 'bytes' = b'',
                       **kwargs: 'Any') -> 'Schema_AuthOption':
        """Make MH authentication option.

        Args:
            type: Option type.
            option: Option data model.
            subtype: Authentication subtype.
            subtype_default: Authentication subtype default value.
            subtype_namespace: Authentication subtype namespace.
            subtype_reversed: Authentication subtype reversed flag.
            spi: Security parameter index.
            data: Authentication data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            subtype_val = option.subtype
            spi = option.spi
            data = option.data
        else:
            subtype_val = self._make_index(subtype, subtype_default, namespace=subtype_namespace,  # type: ignore[assignment]
                                           reversed=subtype_reversed, pack=False)

        if (len(data) + 6) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid format')

        return Schema_AuthOption(
            type=type,
            length=5 + len(data),
            subtype=subtype_val,
            spi=spi,
            data=data,
        )

    def _make_opt_mesg_id(self, type: 'Enum_Option', option: 'Optional[Data_MesgIDOption]' = None, *,
                          timestamp: 'Optional[NTPTimestamp]' = None,
                          interval: 'Optional[dt_type]' = None,
                          **kwargs: 'Any') -> 'Schema_MesgIDOption':
        """Make MH mobility message replay protection option.

        Args:
            type: Option type.
            option: Option data model.
            timestamp: NTP timestamp, c.f., :rfc:`1305`.
            interval: Timestamp interval (since UNIX-epoch).
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            timestamp = option.ntp_timestamp

        if timestamp is None:
            interval = interval or datetime.datetime.now(datetime.timezone.utc)

            int_ts = interval.timestamp()
            ts_sec = math.floor(int_ts)
            ts_frc = math.ceil(((int_ts - ts_sec) * 1_000_000)) * 2**32

            timestamp = NTPTimestamp(seconds=ts_sec + 2_208_988_800,  # 70 years
                                     fraction=ts_frc)

        return Schema_MesgIDOption(
            type=type,
            length=8,
            seconds=timestamp.seconds,
            fraction=timestamp.fraction,
        )

    def _make_opt_cga_pr(self, type: 'Enum_Option', option: 'Optional[Data_CGAParametersRequestOption]' = None,
                         **kwargs: 'Any') -> 'Schema_CGAParametersRequestOption':
        """Make MH CGA parameters request option.

        Args:
            type: Option type.
            option: Option data model.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        return Schema_CGAParametersRequestOption(
            type=type,
            length=0,
        )

    def _make_opt_cga_param(self, type: 'Enum_Option', option: 'Optional[Data_CGAParametersOption]' = None, *,
                            parameters: 'Optional[list[Schema_CGAParameter | Data_CGAParameter | dict[str, Any] | bytes]]' = None,
                            **kwargs: 'Any') -> 'Schema_CGAParametersOption':
        """Make MH CGA paramters option.

        Args:
            type: Option type.
            option: Option data model.
            parameters: CGA parameters.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            parameters = cast('list[Data_CGAParameter]', option.parameters)  # type: ignore[assignment]

        if parameters is None:
            parameters = []

        param = []  # type: list[Schema_CGAParameter | bytes]
        length = 0
        for data in parameters:
            if isinstance(data, bytes):
                length += len(data)
                param.append(data)
            elif isinstance(data, Schema_CGAParameter):
                if not hasattr(data, 'public_key_test'):
                    data.public_key_test = {'len': max(len(data.public_key) - 2, 0)}
                _, ext_len = self._make_cga_extensions(data.extensions)
                length += 25 + len(data.public_key) + ext_len
                param.append(data)
            elif isinstance(data, Data_CGAParameter):
                ext, ext_len = self._make_cga_extensions(data.extensions)
                schema = Schema_CGAParameter(
                    modifier=data.modifier,
                    prefix=data.prefix,
                    collision_count=data.collision_count,
                    public_key=data.public_key,
                    extensions=ext,
                )
                schema.public_key_test = {'len': max(len(data.public_key) - 2, 0)}

                length += 25 + len(data.public_key) + ext_len
                param.append(schema)
            else:
                raise ProtocolError(f'{self.alias}: [OptNo {type}] unknown CGA parameter format: {data}')

        return Schema_CGAParametersOption(
            type=type,
            length=length,
            parameters=param,
        )

    def _make_opt_signature(self, type: 'Enum_Option', option: 'Optional[Data_SignatureOption]' = None, *,
                            signature: 'bytes' = b'',
                            **kwargs: 'Any') -> 'Schema_SignatureOption':
        """Make MH signature option.

        Args:
            type: Option type.
            option: Option data model.
            signature: Signature data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            signature = option.signature

        return Schema_SignatureOption(
            type=type,
            length=len(signature),
            signature=signature,
        )

    def _make_opt_phkt(self, type: 'Enum_Option', option: 'Optional[Data_PermanentHomeKeygenTokenOption]' = None, *,
                       token: 'bytes' = b'',
                       **kwargs: 'Any') -> 'Schema_PermanentHomeKeygenTokenOption':
        """Make MH permanent home keygen token option.

        Args:
            type: Option type.
            option: Option data model.
            token: Token data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            token = option.token

        return Schema_PermanentHomeKeygenTokenOption(
            type=type,
            length=len(token),
            token=token,
        )

    def _make_opt_ct_init(self, type: 'Enum_Option', option: 'Optional[Data_CareofTestInitOption]' = None,
                          **kwargs: 'Any') -> 'Schema_CareofTestInitOption':
        """Make MH Care-of Test Init option.

        Args:
            type: Option type.
            option: Option data model.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        return Schema_CareofTestInitOption(
            type=type,
            length=0,
        )

    def _make_opt_ct(self, type: 'Enum_Option', option: 'Optional[Data_CareofTestOption]' = None,
                     token: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                     **kwargs: 'Any') -> 'Schema_CareofTestOption':
        """Make MH Care-of Test option.

        Args:
            type: Option type.
            option: Option data model.
            token: Care-of keygen token.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            token = option.token

        return Schema_CareofTestOption(
            type=type,
            length=8,
            token=token,
        )

    def _make_opt_exp(self, type: 'Enum_Option', option: 'Optional[Data_ExperimentalMobilityOption]' = None, *,
                      data: 'bytes' = b'',
                      **kwargs: 'Any') -> 'Schema_ExperimentalMobilityOption':
        """Make MH experimental mobility option.

        Args:
            type: Option type.
            option: Option data model.
            data: Experimental data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            data = option.data

        return Schema_ExperimentalMobilityOption(
            type=type,
            length=len(data),
            data=data,
        )

    def _make_opt_badf(self, type: 'Enum_Option', option: 'Optional[Data_BADFOption]' = None, *,
                       spi: 'int' = 0,
                       data: 'bytes' = b'',
                       **kwargs: 'Any') -> 'Schema_BADFOption':
        """Make MH binding authorization data for FMIPv6 (BADF) option.

        Args:
            type: Option type.
            option: Option data model.
            spi: Security parameter index.
            data: Authenticator.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Note:
            The ``length`` field counts the authenticator only, excluding the
            SPI, c.f., :meth:`_read_opt_badf`.

        """
        if option is not None:
            spi = option.spi
            data = option.data

        if not data:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid format')

        return Schema_BADFOption(
            type=type,
            length=len(data),
            spi=spi,
            data=data,
        )

    def _make_opt_ipv6_ap(self, type: 'Enum_Option', option: 'Optional[Data_IPv6AddressPrefixOption]' = None, *,
                          code: 'IPv6AddressPrefixCode | StdlibEnum | AenumEnum | str | int' = IPv6AddressPrefixCode.New_Care_of_Address,
                          code_default: 'Optional[int]' = None,
                          code_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                          code_reversed: 'bool' = False,
                          prefix_length: 'int' = 128,
                          address: 'bytes | str | int | IPv6Address' = '::',
                          **kwargs: 'Any') -> 'Schema_IPv6AddressPrefixOption':
        """Make MH mobility header IPv6 address/prefix option.

        Args:
            type: Option type.
            option: Option data model.
            code: Option code, c.f.,
                :class:`~pcapkit.protocols.internet.mh.IPv6AddressPrefixCode`.
            code_default: Default option code.
            code_namespace: Option code namespace.
            code_reversed: Reverse option code namespace.
            prefix_length: Prefix length.
            address: IPv6 address/prefix.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            code_val = option.code
            prefix_length = option.prefix_length
            address = option.address
        else:
            code_val = self._make_index(code, code_default, namespace=code_namespace,  # type: ignore[assignment]
                                        reversed=code_reversed, pack=False)

        if prefix_length > 128:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid prefix length: {prefix_length}')

        return Schema_IPv6AddressPrefixOption(
            type=type,
            length=18,
            code=code_val,
            prefix_length=prefix_length,
            address=address,
        )

    def _make_opt_dns(self, type: 'Enum_Option', option: 'Optional[Data_DNSUpdateOption]' = None, *,
                      status: 'Enum_DNSStatusCode | StdlibEnum | AenumEnum | str | int' = Enum_DNSStatusCode.DNS_update_performed,
                      status_default: 'Optional[int]' = None,
                      status_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      status_reversed: 'bool' = False,
                      remove: 'bool' = False,
                      identity: 'bytes' = b'',
                      **kwargs: 'Any') -> 'Schema_DNSUpdateOption':
        """Make MH DNS-UPDATE-TYPE option.

        Args:
            type: Option type.
            option: Option data model.
            status: Status.
            status_default: Default status.
            status_namespace: Status namespace.
            status_reversed: Reverse status namespace.
            remove: Remove flag.
            identity: Mobile node identity, in FQDN form.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            status_val = option.status  # type: Enum_DNSStatusCode
            remove = option.remove
            identity = option.identity
        else:
            status_val = self._make_index(status, status_default, namespace=status_namespace,  # type: ignore[assignment]
                                          reversed=status_reversed, pack=False)

        return Schema_DNSUpdateOption(
            type=type,
            length=2 + len(identity),
            status=status_val,
            flags={'R': int(remove)},
            identity=identity,
        )

    def _make_opt_vendor(self, type: 'Enum_Option', option: 'Optional[Data_VendorSpecificOption]' = None, *,
                         vendor: 'int' = 0,
                         subtype: 'int' = 0,
                         data: 'bytes' = b'',
                         **kwargs: 'Any') -> 'Schema_VendorSpecificOption':
        """Make MH vendor specific mobility option.

        Args:
            type: Option type.
            option: Option data model.
            vendor: Vendor ID, an SMI Network Management Private Enterprise
                Number.
            subtype: Vendor-administered sub-type.
            data: Vendor-specific data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            vendor = option.vendor
            subtype = option.subtype
            data = option.data

        return Schema_VendorSpecificOption(
            type=type,
            length=5 + len(data),
            vendor=vendor,
            subtype=subtype,
            data=data,
        )

    def _make_opt_service(self, type: 'Enum_Option', option: 'Optional[Data_ServiceSelectionOption]' = None, *,
                          identifier: 'str' = '',
                          **kwargs: 'Any') -> 'Schema_ServiceSelectionOption':
        """Make MH service selection mobility option.

        Args:
            type: Option type.
            option: Option data model.
            identifier: Service identifier.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            identifier = option.identifier

        encoded = identifier.encode()
        if not encoded:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] service identifier must not be empty')

        return Schema_ServiceSelectionOption(
            type=type,
            length=len(encoded),
            identifier=identifier,
        )

    def _make_opt_hnp(self, type: 'Enum_Option', option: 'Optional[Data_HomeNetworkPrefixOption]' = None, *,
                      prefix_length: 'int' = 64,
                      prefix: 'bytes | str | int | IPv6Address' = '::',
                      **kwargs: 'Any') -> 'Schema_HomeNetworkPrefixOption':
        """Make MH home network prefix option.

        Args:
            type: Option type.
            option: Option data model.
            prefix_length: Prefix length.
            prefix: Home network prefix.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            prefix_length = option.prefix_length
            prefix = option.prefix

        if prefix_length > 128:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid prefix length: {prefix_length}')

        return Schema_HomeNetworkPrefixOption(
            type=type,
            length=18,
            prefix_length=prefix_length,
            prefix=prefix,
        )

    def _make_opt_hi(self, type: 'Enum_Option', option: 'Optional[Data_HandoffIndicatorOption]' = None, *,
                     hi: 'Enum_HandoffType | StdlibEnum | AenumEnum | str | int' = Enum_HandoffType.Attachment_over_a_new_interface,
                     hi_default: 'Optional[int]' = None,
                     hi_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                     hi_reversed: 'bool' = False,
                     **kwargs: 'Any') -> 'Schema_HandoffIndicatorOption':
        """Make MH handoff indicator option.

        Args:
            type: Option type.
            option: Option data model.
            hi: Handoff indicator.
            hi_default: Default handoff indicator.
            hi_namespace: Handoff indicator namespace.
            hi_reversed: Reverse handoff indicator namespace.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            hi_val = option.hi  # type: Enum_HandoffType
        else:
            hi_val = self._make_index(hi, hi_default, namespace=hi_namespace,  # type: ignore[assignment]
                                      reversed=hi_reversed, pack=False)

        return Schema_HandoffIndicatorOption(
            type=type,
            length=2,
            hi=hi_val,
        )

    def _make_opt_att(self, type: 'Enum_Option', option: 'Optional[Data_AccessTechnologyTypeOption]' = None, *,
                      att: 'Enum_AccessType | StdlibEnum | AenumEnum | str | int' = Enum_AccessType.Virtual,
                      att_default: 'Optional[int]' = None,
                      att_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      att_reversed: 'bool' = False,
                      **kwargs: 'Any') -> 'Schema_AccessTechnologyTypeOption':
        """Make MH access technology type option.

        Args:
            type: Option type.
            option: Option data model.
            att: Access technology type.
            att_default: Default access technology type.
            att_namespace: Access technology type namespace.
            att_reversed: Reverse access technology type namespace.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            att_val = option.att  # type: Enum_AccessType
        else:
            att_val = self._make_index(att, att_default, namespace=att_namespace,  # type: ignore[assignment]
                                       reversed=att_reversed, pack=False)

        return Schema_AccessTechnologyTypeOption(
            type=type,
            length=2,
            att=att_val,
        )

    def _make_opt_mn_lli(self, type: 'Enum_Option', option: 'Optional[Data_MNLLIdentifierOption]' = None, *,
                         lli: 'bytes' = b'',
                         **kwargs: 'Any') -> 'Schema_MNLLIdentifierOption':
        """Make MH mobile node link-layer identifier option.

        Args:
            type: Option type.
            option: Option data model.
            lli: Link-layer identifier.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            lli = option.lli

        return Schema_MNLLIdentifierOption(
            type=type,
            length=2 + len(lli),
            lli=lli,
        )

    def _make_opt_lla_addr(self, type: 'Enum_Option', option: 'Optional[Data_LinkLocalAddressOption]' = None, *,
                           address: 'bytes | str | int | IPv6Address' = '::',
                           **kwargs: 'Any') -> 'Schema_LinkLocalAddressOption':
        """Make MH link-local address option.

        Args:
            type: Option type.
            option: Option data model.
            address: Link-local address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            address = option.address

        return Schema_LinkLocalAddressOption(
            type=type,
            length=16,
            address=address,
        )

    def _make_opt_timestamp(self, type: 'Enum_Option', option: 'Optional[Data_TimestampOption]' = None, *,
                            seconds: 'int' = 0,
                            fraction: 'int' = 0,
                            **kwargs: 'Any') -> 'Schema_TimestampOption':
        """Make MH timestamp option.

        Args:
            type: Option type.
            option: Option data model.
            seconds: Seconds since 1 January 1970, in the leading 48 bits.
            fraction: Fraction of a second, in units of 1/65536.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Note:
            The fixed-point pair is taken from
            :attr:`~pcapkit.protocols.data.internet.mh.TimestampOption.pmip_timestamp`
            rather than recomputed from
            :attr:`~pcapkit.protocols.data.internet.mh.TimestampOption.timestamp`,
            since a :class:`~datetime.datetime` holds microseconds and the wire
            format holds 1/65536ths -- converting between them does not round-trip.

        """
        if option is not None:
            seconds, fraction = option.pmip_timestamp

        if not 0 <= seconds < 2 ** 48:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid timestamp seconds: {seconds}')
        if not 0 <= fraction < 2 ** 16:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid timestamp fraction: {fraction}')

        return Schema_TimestampOption(
            type=type,
            length=8,
            timestamp={
                'seconds': seconds,
                'fraction': fraction,
            },
        )

    def _make_opt_restart(self, type: 'Enum_Option', option: 'Optional[Data_RestartCounterOption]' = None, *,
                          counter: 'int' = 0,
                          **kwargs: 'Any') -> 'Schema_RestartCounterOption':
        """Make MH restart counter option.

        Args:
            type: Option type.
            option: Option data model.
            counter: Restart counter.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            counter = option.counter

        return Schema_RestartCounterOption(
            type=type,
            length=4,
            counter=counter,
        )

    def _make_opt_ipv4_hoa(self, type: 'Enum_Option', option: 'Optional[Data_IPv4HomeAddressOption]' = None, *,
                           prefix_length: 'int' = 32,
                           address: 'bytes | str | int | IPv4Address' = '0.0.0.0',
                           request_prefix: 'bool' = False,
                           **kwargs: 'Any') -> 'Schema_IPv4HomeAddressOption':
        """Make MH IPv4 home address option.

        Args:
            type: Option type.
            option: Option data model.
            prefix_length: Prefix length; ``32`` for a single address.
            address: IPv4 home address.
            request_prefix: Mobile network prefix request flag.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            prefix_length = option.prefix_length
            address = option.address
            request_prefix = option.request_prefix

        if prefix_length == 0 or prefix_length > 32:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid prefix length: {prefix_length}')

        return Schema_IPv4HomeAddressOption(
            type=type,
            length=6,
            flags={
                'prefix_length': prefix_length,
                'P': int(request_prefix),
            },
            address=address,
        )

    def _make_opt_ipv4_ack(self, type: 'Enum_Option',
                                                      option: 'Optional[Data_IPv4AddressAcknowledgementOption]' = None, *,
                           status: 'Enum_DSMIPv6HomeAddress | StdlibEnum | AenumEnum | str | int' = Enum_DSMIPv6HomeAddress.Success,
                           status_default: 'Optional[int]' = None,
                           status_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                           status_reversed: 'bool' = False,
                           prefix_length: 'int' = 32,
                           address: 'bytes | str | int | IPv4Address' = '0.0.0.0',
                           **kwargs: 'Any') -> 'Schema_IPv4AddressAcknowledgementOption':
        """Make MH IPv4 address acknowledgement option.

        Args:
            type: Option type.
            option: Option data model.
            status: Status.
            status_default: Default status.
            status_namespace: Status namespace.
            status_reversed: Reverse status namespace.
            prefix_length: Allocated prefix length.
            address: Assigned IPv4 home address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            status_val = option.status  # type: Enum_DSMIPv6HomeAddress
            prefix_length = option.prefix_length
            address = option.address
        else:
            status_val = self._make_index(status, status_default, namespace=status_namespace,  # type: ignore[assignment]
                                          reversed=status_reversed, pack=False)

        if prefix_length > 32:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid prefix length: {prefix_length}')

        return Schema_IPv4AddressAcknowledgementOption(
            type=type,
            length=6,
            status=status_val,
            flags={'prefix_length': prefix_length},
            address=address,
        )

    def _make_opt_nat(self, type: 'Enum_Option', option: 'Optional[Data_NATDetectionOption]' = None, *,
                      force: 'bool' = False,
                      refresh: 'int | timedelta' = 0,
                      **kwargs: 'Any') -> 'Schema_NATDetectionOption':
        """Make MH NAT detection option.

        Args:
            type: Option type.
            option: Option data model.
            force: Force UDP encapsulation flag.
            refresh: Suggested NAT binding refresh interval, in seconds or as a
                :class:`~datetime.timedelta`.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            force = option.force
            refresh_val = math.ceil(option.refresh.total_seconds())
        else:
            refresh_val = refresh if isinstance(refresh, int) else math.ceil(refresh.total_seconds())

        return Schema_NATDetectionOption(
            type=type,
            length=6,
            flags={'F': int(force)},
            refresh=refresh_val,
        )

    def _make_opt_ipv4_coa(self, type: 'Enum_Option', option: 'Optional[Data_IPv4CareofAddressOption]' = None, *,
                           address: 'bytes | str | int | IPv4Address' = '0.0.0.0',
                           **kwargs: 'Any') -> 'Schema_IPv4CareofAddressOption':
        """Make MH IPv4 care-of address option.

        Args:
            type: Option type.
            option: Option data model.
            address: IPv4 care-of address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            address = option.address

        return Schema_IPv4CareofAddressOption(
            type=type,
            length=6,
            address=address,
        )

    def _make_opt_gre(self, type: 'Enum_Option', option: 'Optional[Data_GREKeyOption]' = None, *,
                      key: 'Optional[int]' = None,
                      **kwargs: 'Any') -> 'Schema_GREKeyOption':
        """Make MH GRE key option.

        Args:
            type: Option type.
            option: Option data model.
            key: GRE key identifier, or :obj:`None` to omit it -- which is what an
                option length of 2 means on the wire.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            key = option.key

        return Schema_GREKeyOption(
            type=type,
            length=2 if key is None else 6,
            key=key,
        )

    def _make_opt_bid(self, type: 'Enum_Option', option: 'Optional[Data_BindingIdentifierOption]' = None, *,
                      bid: 'int' = 1,
                      status: 'Enum_StatusCode | StdlibEnum | AenumEnum | str | int' = Enum_StatusCode.Binding_Update_accepted_Proxy_Binding_Update_accepted,
                      status_default: 'Optional[int]' = None,
                      status_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      status_reversed: 'bool' = False,
                      simultaneous: 'bool' = False,
                      bid_pri: 'int' = 0,
                      address: 'Optional[bytes | str | int | IPv4Address | IPv6Address]' = None,
                      **kwargs: 'Any') -> 'Schema_BindingIdentifierOption':
        """Make MH binding identifier (BID) option.

        Args:
            type: Option type.
            option: Option data model.
            bid: Binding identifier.
            status: Status, overriding the message status for this binding alone.
            status_default: Default status.
            status_namespace: Status namespace.
            status_reversed: Reverse status namespace.
            simultaneous: Simultaneous home and foreign binding flag.
            bid_pri: Binding priority.
            address: Care-of address, or :obj:`None` to omit it.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Note:
            The option length is derived from the address family, since that is
            the only thing that carries it on the wire: 4 with no address, 8 for
            an IPv4 one and 20 for an IPv6 one [:rfc:`5648#section-4.3`].

        """
        if option is not None:
            bid = option.bid
            status_val = option.status  # type: Enum_StatusCode
            simultaneous = option.simultaneous
            bid_pri = option.bid_pri
            address = option.address
        else:
            status_val = self._make_index(status, status_default, namespace=status_namespace,  # type: ignore[assignment]
                                          reversed=status_reversed, pack=False)

        if bid_pri > 0x7F:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid binding priority: {bid_pri}')

        if address is None:
            length = 4
        else:
            addr = ipaddress.ip_address(address) if not isinstance(
                address, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else address
            length = 8 if addr.version == 4 else 20
            address = addr

        return Schema_BindingIdentifierOption(
            type=type,
            length=length,
            bid=bid,
            status=status_val,
            flags={
                'H': int(simultaneous),
                'BID_PRI': bid_pri,
            },
            address=address,
        )

    def _make_opt_ipv4_hoa_req(self, type: 'Enum_Option',
                                                          option: 'Optional[Data_IPv4HomeAddressRequestOption]' = None, *,
                               prefix_length: 'int' = 32,
                               address: 'bytes | str | int | IPv4Address' = '0.0.0.0',
                               **kwargs: 'Any') -> 'Schema_IPv4HomeAddressRequestOption':
        """Make MH IPv4 home address request option.

        Args:
            type: Option type.
            option: Option data model.
            prefix_length: Prefix length of the requested home network.
            address: Requested IPv4 home address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            prefix_length = option.prefix_length
            address = option.address

        if prefix_length > 32:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid prefix length: {prefix_length}')

        return Schema_IPv4HomeAddressRequestOption(
            type=type,
            length=6,
            flags={'prefix_length': prefix_length},
            address=address,
        )

    def _make_opt_ipv4_hoa_rep(self, type: 'Enum_Option', option: 'Optional[Data_IPv4HomeAddressReplyOption]' = None, *,
                               status: 'Enum_HomeAddressReply | StdlibEnum | AenumEnum | str | int' = Enum_HomeAddressReply.Success,
                               status_default: 'Optional[int]' = None,
                               status_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                               status_reversed: 'bool' = False,
                               prefix_length: 'int' = 32,
                               address: 'bytes | str | int | IPv4Address' = '0.0.0.0',
                               **kwargs: 'Any') -> 'Schema_IPv4HomeAddressReplyOption':
        """Make MH IPv4 home address reply option.

        Args:
            type: Option type.
            option: Option data model.
            status: Status.
            status_default: Default status.
            status_namespace: Status namespace.
            status_reversed: Reverse status namespace.
            prefix_length: Prefix length of the assigned home network.
            address: Assigned IPv4 home address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            status_val = option.status  # type: Enum_HomeAddressReply
            prefix_length = option.prefix_length
            address = option.address
        else:
            status_val = self._make_index(status, status_default, namespace=status_namespace,  # type: ignore[assignment]
                                          reversed=status_reversed, pack=False)

        if prefix_length > 32:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid prefix length: {prefix_length}')

        return Schema_IPv4HomeAddressReplyOption(
            type=type,
            length=6,
            status=status_val,
            flags={'prefix_length': prefix_length},
            address=address,
        )

    def _make_opt_ipv4_router(self, type: 'Enum_Option',
                                                         option: 'Optional[Data_IPv4DefaultRouterAddressOption]' = None, *,
                              address: 'bytes | str | int | IPv4Address' = '0.0.0.0',
                              **kwargs: 'Any') -> 'Schema_IPv4DefaultRouterAddressOption':
        """Make MH IPv4 default-router address option.

        Args:
            type: Option type.
            option: Option data model.
            address: IPv4 default-router address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            address = option.address

        return Schema_IPv4DefaultRouterAddressOption(
            type=type,
            length=6,
            address=address,
        )

    def _make_opt_ipv4_dhcp(self, type: 'Enum_Option', option: 'Optional[Data_IPv4DHCPSupportModeOption]' = None, *,
                            mode: 'Enum_DHCPSupportMode | StdlibEnum | AenumEnum | str | int' = Enum_DHCPSupportMode.Unassigned_0x0,
                            mode_default: 'Optional[int]' = None,
                            mode_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                            mode_reversed: 'bool' = False,
                            **kwargs: 'Any') -> 'Schema_IPv4DHCPSupportModeOption':
        """Make MH IPv4 DHCP support mode option.

        Args:
            type: Option type.
            option: Option data model.
            mode: DHCP support mode.
            mode_default: Default DHCP support mode.
            mode_namespace: DHCP support mode namespace.
            mode_reversed: Reverse DHCP support mode namespace.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            mode_val = int(option.mode)
        else:
            mode_val = self._make_index(mode, mode_default, namespace=mode_namespace,
                                        reversed=mode_reversed, pack=False)

        if mode_val > 1:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid DHCP support mode: {mode_val}')

        return Schema_IPv4DHCPSupportModeOption(
            type=type,
            length=2,
            flags={'S': mode_val},
        )

    def _make_opt_cr(self, type: 'Enum_Option', option: 'Optional[Data_ContextRequestOption]' = None, *,
                     requests: 'Optional[list[Data_ContextRequest | tuple[Enum_Option | int, bytes]]]' = None,
                     **kwargs: 'Any') -> 'Schema_ContextRequestOption':
        """Make MH context request option.

        Args:
            type: Option type.
            option: Option data model.
            requests: Requested contexts, each either a data model or a
                ``(mobility option type, extra data)`` pair.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            requests = cast('list[Data_ContextRequest | tuple[Enum_Option | int, bytes]]',
                            list(option.requests))
        else:
            requests = requests or []

        buffer = bytearray()
        for request in requests:
            if isinstance(request, Data_ContextRequest):
                req_type, value = int(request.type), request.value
            else:
                raw_type, value = request
                req_type = int(raw_type)

            if len(value) > 0xFF:
                raise ProtocolError(f'{self.alias}: [OptNo {type}] context request value of '
                                    f'{len(value)} octets does not fit its length field')

            buffer.append(req_type)
            buffer.append(len(value))
            buffer.extend(value)

        return Schema_ContextRequestOption(
            type=type,
            length=2 + len(buffer),
            requests=bytes(buffer),
        )

    def _make_opt_lmaa(self, type: 'Enum_Option', option: 'Optional[Data_LMAAddressOption]' = None, *,
                       code: 'LMAAddressCode | StdlibEnum | AenumEnum | str | int' = LMAAddressCode.IPv6_LMAA,
                       code_default: 'Optional[int]' = None,
                       code_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                       code_reversed: 'bool' = False,
                       address: 'bytes | str | int | IPv4Address | IPv6Address' = '::',
                       **kwargs: 'Any') -> 'Schema_LMAAddressOption':
        """Make MH local mobility anchor address option.

        Args:
            type: Option type.
            option: Option data model.
            code: Option code, c.f.,
                :class:`~pcapkit.protocols.internet.mh.LMAAddressCode`.
            code_default: Default option code.
            code_namespace: Option code namespace.
            code_reversed: Reverse option code namespace.
            address: Local mobility anchor address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Note:
            The option length is derived from the address family rather than from
            :attr:`code`, so that the two cannot be emitted disagreeing.

        """
        if option is not None:
            code_val = int(option.code)
            address = option.address
        else:
            code_val = self._make_index(code, code_default, namespace=code_namespace,
                                        reversed=code_reversed, pack=False)

        if isinstance(address, bytes) and len(address) not in (4, 16):
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid address: {address!r}')

        # NOTE: The address is normalised rather than passed through, so that the
        # schema attribute holds the same type it would after a parse. The width is
        # then taken from the address itself rather than from ``code``, so that the
        # two cannot be emitted disagreeing.
        if isinstance(address, bytes):
            addr = ipaddress.ip_address(address)  # type: IPv4Address | IPv6Address
        elif isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            addr = address
        else:
            addr = ipaddress.ip_address(address)

        return Schema_LMAAddressOption(
            type=type,
            length=6 if addr.version == 4 else 18,
            code=code_val,
            address=addr,
        )

    def _make_opt_mn_lla_iid(self, type: 'Enum_Option', option: 'Optional[Data_MNLLAIIDOption]' = None, *,
                             iid: 'bytes' = b'\x00' * 8,
                             **kwargs: 'Any') -> 'Schema_MNLLAIIDOption':
        """Make MH mobile node link-local address interface identifier option.

        Args:
            type: Option type.
            option: Option data model.
            iid: Interface identifier; exactly 8 octets.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            iid = option.iid

        if len(iid) != 8:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid interface identifier: {iid!r}')

        return Schema_MNLLAIIDOption(
            type=type,
            length=10,
            iid=iid,
        )

    def _make_opt_transient(self, type: 'Enum_Option', option: 'Optional[Data_TransientBindingOption]' = None, *,
                            late: 'bool' = False,
                            lifetime: 'int | timedelta' = 0,
                            **kwargs: 'Any') -> 'Schema_TransientBindingOption':
        """Make MH transient binding option.

        Args:
            type: Option type.
            option: Option data model.
            late: Late path switch flag.
            lifetime: Maximum lifetime of the transient state, in units of 100
                milliseconds or as a :class:`~datetime.timedelta`.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            late = option.late
            lifetime_val = math.ceil(option.lifetime.total_seconds() * 10)
        else:
            lifetime_val = lifetime if isinstance(lifetime, int) else math.ceil(
                lifetime.total_seconds() * 10)

        if lifetime_val > 0xFF:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid lifetime: {lifetime_val}')

        return Schema_TransientBindingOption(
            type=type,
            length=2,
            flags={'L': int(late)},
            lifetime=lifetime_val,
        )

    def _make_opt_fs(self, type: 'Enum_Option', option: 'Optional[Data_FlowSummaryOption]' = None, *,
                     fid: 'Optional[list[int]]' = None,
                     **kwargs: 'Any') -> 'Schema_FlowSummaryOption':
        """Make MH flow summary mobility option.

        Args:
            type: Option type.
            option: Option data model.
            fid: Flow identifiers being refreshed.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            fid = list(option.fid)
        else:
            fid = fid or []

        return Schema_FlowSummaryOption(
            type=type,
            length=len(fid) * 2,
            fid=fid,
        )

    def _make_fid_suboptions(
        self,
        suboptions: 'FlowIDSuboption | list[Schema_FlowIdentificationSuboption | tuple[Enum_FlowIDSuboption, dict[str, Any]] | bytes]',
    ) -> 'list[Schema_FlowIdentificationSuboption | bytes]':
        """Make MH flow identification sub-options.

        Args:
            suboptions: Sub-options, as parsed data, schemas, ``(type, kwargs)``
                pairs, or raw octets.

        Returns:
            Sub-option schema list.

        """
        if isinstance(suboptions, list):
            entries = []  # type: list[Schema_FlowIdentificationSuboption | bytes]
            for item in suboptions:
                if isinstance(item, (bytes, Schema)):
                    entries.append(cast('Schema_FlowIdentificationSuboption | bytes', item))
                else:
                    code, args = cast('tuple[Enum_FlowIDSuboption, dict[str, Any]]', item)
                    entries.append(self._make_fid_suboption(code, **args))
            return entries

        return [self._make_fid_suboption(code, option)
                for code, option in suboptions.items(multi=True)]

    def _make_fid_suboption(self, code: 'Enum_FlowIDSuboption',
                            option: 'Optional[Data_FlowIdentificationSuboption]' = None,
                            **kwargs: 'Any') -> 'Schema_FlowIdentificationSuboption':
        """Make one MH flow identification sub-option.

        Args:
            code: Sub-option type.
            option: Sub-option data model.
            **kwargs: Sub-option fields, when no data model is given.

        Returns:
            Constructed sub-option schema.

        Note:
            The data model parameter is named ``option`` rather than ``data`` to
            match :meth:`_make_opt_fid` and the rest of this module -- and because
            naming it ``data`` made it **shadow a field**. The traffic selector and
            unassigned sub-options both carry a field of their own called ``data``,
            so a caller's ``data=`` bound to the model parameter instead of landing
            in ``**kwargs``, and the ``kwargs.get('data')`` fallback below could
            never see it: the payload was silently dropped and the length written as
            though it were empty. No exception, just a lost field.

            Dispatch is on ``code`` rather than on ``isinstance`` of the schema or
            data class, for the reason given in :meth:`_read_fid_suboptions`.

        """
        if code in (Enum_FlowIDSuboption.Pad, Enum_FlowIDSuboption.PadN):
            if code == Enum_FlowIDSuboption.Pad:
                pad_len = 0
            elif option is not None:
                pad_len = option.length - 2
            else:
                pad_len = cast('int', kwargs.get('length', 0))
            return Schema_PadFlowIdentificationSuboption(type=code, length=pad_len)

        if code == Enum_FlowIDSuboption.BID_Reference:
            if option is not None:
                bid = list(cast('Data_BIDReferenceSuboption', option).bid)
            else:
                bid = cast('list[int]', kwargs.get('bid') or [])
            return Schema_BIDReferenceSuboption(type=code, length=len(bid) * 2, bid=bid)

        if code == Enum_FlowIDSuboption.Traffic_Selector:
            if option is not None:
                selector_opt = cast('Data_TrafficSelectorSuboption', option)
                ts_format = selector_opt.ts_format  # type: Enum_TrafficSelector | int
                selector = selector_opt.selector
            else:
                ts_format = cast('Enum_TrafficSelector | int',
                                 kwargs.get('ts_format',
                                            Enum_TrafficSelector.IPv6_Binary_Traffic_Selector))
                selector = cast('bytes', kwargs.get('selector', b''))
            return Schema_TrafficSelectorSuboption(
                type=code, length=2 + len(selector),
                ts_format=cast('Enum_TrafficSelector', ts_format), selector=selector)

        if code == Enum_FlowIDSuboption.Flow_Binding_Action:
            if option is not None:
                action = cast('Data_FlowBindingActionSuboption',
                              option).action  # type: Enum_FlowBindingAction | int
            else:
                action = cast('Enum_FlowBindingAction | int',
                              kwargs.get('action', Enum_FlowBindingAction.Add))
            return Schema_FlowBindingActionSuboption(
                type=code, length=2, action=cast('Enum_FlowBindingAction', action))

        if code == Enum_FlowIDSuboption.Target_Care_of_Address:
            if option is not None:
                address = cast('Data_TargetCareofAddressSuboption', option).address  # type: Any
            else:
                address = kwargs.get('address', '::')
            addr = address if isinstance(
                address, (ipaddress.IPv4Address, ipaddress.IPv6Address)
            ) else ipaddress.ip_address(address)
            return Schema_TargetCareofAddressSuboption(
                type=code, length=6 if addr.version == 4 else 18, address=addr)

        if option is not None:
            payload = cast('Data_UnassignedFlowIdentificationSuboption', option).data
        else:
            payload = cast('bytes', kwargs.get('data', b''))
        return Schema_UnassignedFlowIdentificationSuboption(
            type=code, length=len(payload), data=payload)

    def _make_opt_fid(self, type: 'Enum_Option', option: 'Optional[Data_FlowIdentificationOption]' = None, *,
                      fid: 'int' = 1,
                      fid_pri: 'int' = 1,
                      status: 'Enum_FlowIDStatus | StdlibEnum | AenumEnum | str | int' = Enum_FlowIDStatus.Flow_binding_successful,
                      status_default: 'Optional[int]' = None,
                      status_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      status_reversed: 'bool' = False,
                      suboptions: 'Optional[FlowIDSuboption | list[Schema_FlowIdentificationSuboption | tuple[Enum_FlowIDSuboption, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_FlowIdentificationOption':
        """Make MH flow identification mobility option.

        Args:
            type: Option type.
            option: Option data model.
            fid: Flow identifier.
            fid_pri: Flow priority.
            status: Status.
            status_default: Default status.
            status_namespace: Status namespace.
            status_reversed: Reverse status namespace.
            suboptions: Sub-options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            fid = option.fid
            fid_pri = option.fid_pri
            status_val = option.status  # type: Enum_FlowIDStatus
            suboptions = option.suboptions
        else:
            status_val = self._make_index(status, status_default, namespace=status_namespace,  # type: ignore[assignment]
                                          reversed=status_reversed, pack=False)
            suboptions = suboptions or []

        entries = self._make_fid_suboptions(suboptions)
        length = 6 + sum(len(entry) if isinstance(entry, bytes) else len(entry.pack())
                         for entry in entries)

        return Schema_FlowIdentificationOption(
            type=type,
            length=length,
            fid=fid,
            fid_pri=fid_pri,
            status=status_val,
            suboptions=entries,
        )

    def _make_opt_rc(self, type: 'Enum_Option', option: 'Optional[Data_RedirectCapabilityOption]' = None,
                     **kwargs: 'Any') -> 'Schema_RedirectCapabilityOption':
        """Make MH redirect-capability mobility option.

        Args:
            type: Option type.
            option: Option data model.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        return Schema_RedirectCapabilityOption(
            type=type,
            length=2,
        )

    def _make_opt_redirect(self, type: 'Enum_Option', option: 'Optional[Data_RedirectOption]' = None, *,
                           ipv6: 'Optional[bytes | str | int | IPv6Address]' = None,
                           ipv4: 'Optional[bytes | str | int | IPv4Address]' = None,
                           **kwargs: 'Any') -> 'Schema_RedirectOption':
        """Make MH redirect mobility option.

        Args:
            type: Option type.
            option: Option data model.
            ipv6: IPv6 address of the redirected-to local mobility anchor.
            ipv4: IPv4 address of the redirected-to local mobility anchor.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If neither or both addresses are given.
                :rfc:`6463#section-4.2` requires exactly one.

        """
        if option is not None:
            ipv6 = option.ipv6
            ipv4 = option.ipv4

        if (ipv6 is None) == (ipv4 is None):
            raise ProtocolError(f'{self.alias}: [OptNo {type}] exactly one of the IPv6 and '
                                'IPv4 addresses must be given')

        return Schema_RedirectOption(
            type=type,
            length=18 if ipv6 is not None else 6,
            flags={
                'K': int(ipv6 is not None),
                'N': int(ipv4 is not None),
            },
            ipv6=ipv6,
            ipv4=ipv4,
        )

    def _make_opt_load(self, type: 'Enum_Option', option: 'Optional[Data_LoadInformationOption]' = None, *,
                       priority: 'int' = 0,
                       sessions_in_use: 'int' = 0,
                       max_sessions: 'int' = 0,
                       used_capacity: 'int' = 0,
                       max_capacity: 'int' = 0,
                       **kwargs: 'Any') -> 'Schema_LoadInformationOption':
        """Make MH load information mobility option.

        Args:
            type: Option type.
            option: Option data model.
            priority: Priority; a lower value is a higher priority.
            sessions_in_use: Mobility sessions currently in use.
            max_sessions: Maximum number of mobility sessions accepted.
            used_capacity: Used capacity, in kilobytes per second.
            max_capacity: Maximum capacity, in kilobytes per second.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            priority = option.priority
            sessions_in_use = option.sessions_in_use
            max_sessions = option.max_sessions
            used_capacity = option.used_capacity
            max_capacity = option.max_capacity

        return Schema_LoadInformationOption(
            type=type,
            length=18,
            priority=priority,
            sessions_in_use=sessions_in_use,
            max_sessions=max_sessions,
            used_capacity=used_capacity,
            max_capacity=max_capacity,
        )

    def _make_opt_alt_ipv4_coa(self, type: 'Enum_Option',
                                                          option: 'Optional[Data_AlternateIPv4CareofAddressOption]' = None, *,
                               address: 'bytes | str | int | IPv4Address' = '0.0.0.0',
                               **kwargs: 'Any') -> 'Schema_AlternateIPv4CareofAddressOption':
        """Make MH alternate IPv4 care-of address option.

        Args:
            type: Option type.
            option: Option data model.
            address: Alternate IPv4 care-of address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            address = option.address

        return Schema_AlternateIPv4CareofAddressOption(
            type=type,
            length=4,
            address=address,
        )

    def _make_opt_mn_group(self, type: 'Enum_Option', option: 'Optional[Data_MNGroupIdentifierOption]' = None, *,
                           subtype: 'Enum_MNGroupID | StdlibEnum | AenumEnum | str | int' = Enum_MNGroupID.Bulk_Binding_Update_Group,
                           subtype_default: 'Optional[int]' = None,
                           subtype_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                           subtype_reversed: 'bool' = False,
                           group_id: 'int' = 1,
                           **kwargs: 'Any') -> 'Schema_MNGroupIdentifierOption':
        """Make MH mobile node group identifier option.

        Args:
            type: Option type.
            option: Option data model.
            subtype: Sub-type.
            subtype_default: Default sub-type.
            subtype_namespace: Sub-type namespace.
            subtype_reversed: Reverse sub-type namespace.
            group_id: Mobile node group identifier.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            subtype_val = option.subtype  # type: Enum_MNGroupID
            group_id = option.group_id
        else:
            subtype_val = self._make_index(subtype, subtype_default, namespace=subtype_namespace,  # type: ignore[assignment]
                                           reversed=subtype_reversed, pack=False)

        return Schema_MNGroupIdentifierOption(
            type=type,
            length=6,
            subtype=subtype_val,
            group_id=group_id,
        )

    def _make_opt_mag_addr(self, type: 'Enum_Option', option: 'Optional[Data_MAGIPv6AddressOption]' = None, *,
                           address_length: 'int' = 128,
                           address: 'bytes | str | int | IPv6Address' = '::',
                           **kwargs: 'Any') -> 'Schema_MAGIPv6AddressOption':
        """Make MH MAG IPv6 address option.

        Args:
            type: Option type.
            option: Option data model.
            address_length: Address length, in bits; :rfc:`6705#section-11.1`
                requires 128.
            address: MAG IPv6 address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            address_length = option.address_length
            address = option.address

        return Schema_MAGIPv6AddressOption(
            type=type,
            length=18,
            address_length=address_length,
            address=address,
        )

    def _make_ani_suboptions(
        self,
        suboptions: 'ANISuboption | list[Schema_ANISuboption | tuple[Enum_ANISuboption, dict[str, Any]] | bytes]',
    ) -> 'list[Schema_ANISuboption | bytes]':
        """Make MH access network identifier sub-options.

        Args:
            suboptions: Sub-options, as parsed data, schemas, ``(type, kwargs)``
                pairs, or raw octets.

        Returns:
            Sub-option schema list.

        """
        if isinstance(suboptions, list):
            entries = []  # type: list[Schema_ANISuboption | bytes]
            for item in suboptions:
                if isinstance(item, (bytes, Schema)):
                    entries.append(cast('Schema_ANISuboption | bytes', item))
                else:
                    code, args = cast('tuple[Enum_ANISuboption, dict[str, Any]]', item)
                    entries.append(self._make_ani_suboption(code, **args))
            return entries

        return [self._make_ani_suboption(code, option)
                for code, option in suboptions.items(multi=True)]

    def _make_ani_suboption(self, code: 'Enum_ANISuboption',
                            option: 'Optional[Data_ANISuboption]' = None,
                            **kwargs: 'Any') -> 'Schema_ANISuboption':
        """Make one MH access network identifier sub-option.

        Args:
            code: Sub-option type.
            option: Sub-option data model.
            **kwargs: Sub-option fields, when no data model is given.

        Returns:
            Constructed sub-option schema.

        Note:
            The geo-location degrees are re-encoded from the **raw** signed
            integers rather than from the decoded floats, since a float cannot
            always be converted back to the same 24-bit fixed-point value.

            The data model parameter is named ``option`` rather than ``data`` so
            that it cannot shadow a sub-option field of that name -- see
            :meth:`_make_fid_suboption`, where it did. Dispatch is on ``code``
            rather than on ``isinstance``, for the reason given in
            :meth:`_read_fid_suboptions`.

        """
        if code == Enum_ANISuboption.Network_Identifier:
            if option is not None:
                net = cast('Data_ANINetworkIdentifierSuboption', option)
                utf8, net_name, ap_name = net.utf8, net.net_name, net.ap_name
            else:
                utf8 = cast('bool', kwargs.get('utf8', False))
                net_name = cast('bytes', kwargs.get('net_name', b''))
                ap_name = cast('bytes', kwargs.get('ap_name', b''))
            return Schema_ANINetworkIdentifierSuboption(
                type=code, length=3 + len(net_name) + len(ap_name),
                flags={'E': int(utf8)}, net_name_len=len(net_name), net_name=net_name,
                ap_name_len=len(ap_name), ap_name=ap_name)

        if code == Enum_ANISuboption.Geo_Location:
            if option is not None:
                geo = cast('Data_ANIGeoLocationSuboption', option)
                raw_lat, raw_lon = geo.raw_latitude, geo.raw_longitude
            else:
                raw_lat = cast('int', kwargs.get('raw_latitude', 0))
                raw_lon = cast('int', kwargs.get('raw_longitude', 0))
            return Schema_ANIGeoLocationSuboption(
                type=code, length=6, location={
                    'latitude': raw_lat & 0xFFFFFF,
                    'longitude': raw_lon & 0xFFFFFF,
                })

        if code == Enum_ANISuboption.Operator_Identifier:
            if option is not None:
                operator = cast('Data_ANIOperatorIdentifierSuboption', option)
                op_id_type = operator.op_id_type  # type: Enum_OperatorID | int
                identifier = operator.identifier
            else:
                op_id_type = cast('Enum_OperatorID | int',
                                  kwargs.get('op_id_type', Enum_OperatorID.Realm_of_the_Operator))
                identifier = cast('bytes', kwargs.get('identifier', b''))
            return Schema_ANIOperatorIdentifierSuboption(
                type=code, length=1 + len(identifier),
                op_id_type=cast('Enum_OperatorID', op_id_type), identifier=identifier)

        if code == Enum_ANISuboption.Civic_Location:
            if option is not None:
                civic = cast('Data_ANICivicLocationSuboption', option)
                fmt, location = civic.format, civic.location
            else:
                fmt = cast('int', kwargs.get('format', 0))
                location = cast('bytes', kwargs.get('location', b''))
            return Schema_ANICivicLocationSuboption(
                type=code, length=2 + len(location), format=fmt, location=location)

        if code == Enum_ANISuboption.MAG_Group_Identifier:
            if option is not None:
                group_id = cast('Data_ANIMAGGroupIdentifierSuboption', option).group_id
            else:
                group_id = cast('int', kwargs.get('group_id', 0))
            return Schema_ANIMAGGroupIdentifierSuboption(type=code, length=2, group_id=group_id)

        if code == Enum_ANISuboption.ANI_Update_Timer:
            if option is not None:
                timer = math.ceil(cast('Data_ANIUpdateTimerSuboption',
                                       option).timer.total_seconds() / 4)
            else:
                raw_timer = kwargs.get('timer', 0)
                timer = raw_timer if isinstance(raw_timer, int) else math.ceil(
                    raw_timer.total_seconds() / 4)
            return Schema_ANIUpdateTimerSuboption(type=code, length=2, timer=timer)

        if option is not None:
            payload = cast('Data_UnassignedANISuboption', option).data
        else:
            payload = cast('bytes', kwargs.get('data', b''))
        return Schema_UnassignedANISuboption(type=code, length=len(payload), data=payload)

    def _make_opt_ani(self, type: 'Enum_Option', option: 'Optional[Data_AccessNetworkIdentifierOption]' = None, *,
                      suboptions: 'Optional[ANISuboption | list[Schema_ANISuboption | tuple[Enum_ANISuboption, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_AccessNetworkIdentifierOption':
        """Make MH access network identifier option.

        Args:
            type: Option type.
            option: Option data model.
            suboptions: Sub-options; at least one is required.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            suboptions = option.suboptions
        else:
            suboptions = suboptions or []

        entries = self._make_ani_suboptions(suboptions)
        if not entries:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] at least one sub-option is required')

        length = sum(len(entry) if isinstance(entry, bytes) else len(entry.pack())
                     for entry in entries)

        return Schema_AccessNetworkIdentifierOption(
            type=type,
            length=length,
            suboptions=entries,
        )

    def _make_opt_offload(self, type: 'Enum_Option',
                                                     option: 'Optional[Data_IPv4TrafficOffloadSelectorOption]' = None, *,
                          mode: 'bool' = False,
                          selector: 'Optional[FlowIDSuboption | list[Schema_FlowIdentificationSuboption | tuple[Enum_FlowIDSuboption, dict[str, Any]] | bytes]]' = None,
                          **kwargs: 'Any') -> 'Schema_IPv4TrafficOffloadSelectorOption':
        """Make MH IPv4 traffic offload selector option.

        Args:
            type: Option type.
            option: Option data model.
            mode: Offload mode flag.
            selector: Traffic selector sub-options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            mode = option.mode
            selector = option.selector
        else:
            selector = selector or []

        entries = self._make_fid_suboptions(selector)
        length = 4 + sum(len(entry) if isinstance(entry, bytes) else len(entry.pack())
                         for entry in entries)

        return Schema_IPv4TrafficOffloadSelectorOption(
            type=type,
            length=length,
            flags={'M': int(mode)},
            selector=entries,
        )

    def _make_opt_mcast_sel(self, type: 'Enum_Option',
                                                       option: 'Optional[Data_DynamicIPMulticastSelectorOption]' = None, *,
                            protocol: 'int' = 143,
                            mode: 'bool' = False,
                            records: 'int' = 0,
                            data: 'bytes' = b'',
                            **kwargs: 'Any') -> 'Schema_DynamicIPMulticastSelectorOption':
        """Make MH dynamic IP multicast selector option.

        Args:
            type: Option type.
            option: Option data model.
            protocol: MLD or IGMP protocol number identifying the record format.
            mode: Selector mode flag.
            records: Number of multicast address records in ``data``.
            data: Multicast address records, opaque to this module.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            protocol = option.protocol
            mode = option.mode
            records = option.records
            data = option.data

        return Schema_DynamicIPMulticastSelectorOption(
            type=type,
            length=4 + len(data),
            protocol=protocol,
            flags={'M': int(mode)},
            records=records,
            data=data,
        )

    def _make_opt_dmnp(self, type: 'Enum_Option', option: 'Optional[Data_DelegatedMNPOption]' = None, *,
                       prefix_length: 'int' = 64,
                       prefix: 'bytes | str | int | IPv4Address | IPv6Address' = '::',
                       **kwargs: 'Any') -> 'Schema_DelegatedMNPOption':
        """Make MH delegated mobile network prefix option.

        Args:
            type: Option type.
            option: Option data model.
            prefix_length: Prefix length.
            prefix: Delegated mobile network prefix.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Note:
            The ``V`` flag is derived from the prefix's own family rather than
            taken as an argument, so that the flag and the emitted width cannot
            disagree.

        """
        if option is not None:
            prefix_length = option.prefix_length
            prefix = option.prefix

        addr = prefix if isinstance(
            prefix, (ipaddress.IPv4Address, ipaddress.IPv6Address)
        ) else ipaddress.ip_address(prefix)
        ipv4 = addr.version == 4

        if prefix_length > (32 if ipv4 else 128):
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid prefix length: {prefix_length}')

        return Schema_DelegatedMNPOption(
            type=type,
            length=6 if ipv4 else 18,
            flags={'V': int(ipv4)},
            prefix_length=prefix_length,
            prefix=addr,
        )

    def _make_opt_ams4(self, type: 'Enum_Option',
                                                  option: 'Optional[Data_ActiveMulticastSubscriptionIPv4Option]' = None, *,
                       igmp_type: 'int' = 0x22,
                       context: 'bytes' = b'',
                       **kwargs: 'Any') -> 'Schema_ActiveMulticastSubscriptionIPv4Option':
        """Make MH active multicast subscription IPv4 option.

        Args:
            type: Option type.
            option: Option data model.
            igmp_type: IGMP message type identifying the context format.
            context: Multicast membership context, opaque to this module.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            igmp_type = option.igmp_type
            context = option.context

        return Schema_ActiveMulticastSubscriptionIPv4Option(
            type=type,
            length=1 + len(context),
            igmp_type=igmp_type,
            context=context,
        )

    def _make_opt_ams6(self, type: 'Enum_Option',
                                                  option: 'Optional[Data_ActiveMulticastSubscriptionIPv6Option]' = None, *,
                       mld_type: 'int' = 143,
                       context: 'bytes' = b'',
                       **kwargs: 'Any') -> 'Schema_ActiveMulticastSubscriptionIPv6Option':
        """Make MH active multicast subscription IPv6 option.

        Args:
            type: Option type.
            option: Option data model.
            mld_type: MLD message type identifying the context format.
            context: Multicast membership context, opaque to this module.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            mld_type = option.mld_type
            context = option.context

        return Schema_ActiveMulticastSubscriptionIPv6Option(
            type=type,
            length=1 + len(context),
            mld_type=mld_type,
            context=context,
        )

    def _make_qos_attributes(
        self,
        attributes: 'QoSAttribute | list[Schema_QoSAttribute | tuple[Enum_QoSAttribute, dict[str, Any]] | bytes]',
    ) -> 'list[Schema_QoSAttribute | bytes]':
        """Make MH quality-of-service attributes.

        Args:
            attributes: Attributes, as parsed data, schemas, ``(type, kwargs)``
                pairs, or raw octets.

        Returns:
            Attribute schema list.

        """
        if isinstance(attributes, list):
            entries = []  # type: list[Schema_QoSAttribute | bytes]
            for item in attributes:
                if isinstance(item, (bytes, Schema)):
                    entries.append(cast('Schema_QoSAttribute | bytes', item))
                else:
                    code, args = cast('tuple[Enum_QoSAttribute, dict[str, Any]]', item)
                    entries.append(self._make_qos_attribute(code, **args))
            return entries

        return [self._make_qos_attribute(code, option)
                for code, option in attributes.items(multi=True)]

    def _make_qos_attribute(self, code: 'Enum_QoSAttribute',
                            option: 'Optional[Data_QoSAttribute]' = None,
                            **kwargs: 'Any') -> 'Schema_QoSAttribute':
        """Make one MH quality-of-service attribute.

        Args:
            code: Attribute type.
            option: Attribute data model.
            **kwargs: Attribute fields, when no data model is given.

        Returns:
            Constructed attribute schema.

        Note:
            The data model parameter is named ``option`` rather than ``data``, and
            that is not cosmetic. The vendor-specific attribute of
            :rfc:`7222#section-4.2.11` has a field of its own called ``data``, so
            with the parameter named ``data`` a caller's ``data=`` bound to the
            model parameter instead of reaching ``**kwargs`` -- and the
            ``kwargs.get('data')`` fallback then always saw nothing. Building the
            attribute the natural way, mirroring the data model's own field names,
            silently dropped the vendor payload and wrote the length as though it
            were empty. ``vendor`` and ``subtype`` survived because those names do
            not collide, which made the loss look like a partial success rather
            than a bug.

            Dispatch is on ``code`` rather than on ``isinstance``, for the reason
            given in :meth:`_read_fid_suboptions`.

        """
        if code in (Enum_QoSAttribute.Per_Session_Agg_Max_DL_Bit_Rate,
                    Enum_QoSAttribute.Per_Session_Agg_Max_UL_Bit_Rate):
            if option is not None:
                session = cast('Data_PerSessionBitRateAttribute', option)
                service, exclude, rate = session.service, session.exclude, session.rate
            else:
                service = cast('bool', kwargs.get('service', False))
                exclude = cast('bool', kwargs.get('exclude', False))
                rate = cast('int', kwargs.get('rate', 0))
            return Schema_PerSessionBitRateAttribute(
                type=code, length=6,
                flags={'S': int(service), 'E': int(exclude)}, rate=rate)

        if code in (Enum_QoSAttribute.Per_MN_Agg_Max_DL_Bit_Rate,
                    Enum_QoSAttribute.Per_MN_Agg_Max_UL_Bit_Rate,
                    Enum_QoSAttribute.Aggregate_Max_DL_Bit_Rate,
                    Enum_QoSAttribute.Aggregate_Max_UL_Bit_Rate,
                    Enum_QoSAttribute.Guaranteed_DL_Bit_Rate,
                    Enum_QoSAttribute.Guaranteed_UL_Bit_Rate):
            if option is not None:
                rate = cast('Data_BitRateAttribute', option).rate
            else:
                rate = cast('int', kwargs.get('rate', 0))
            return Schema_BitRateAttribute(type=code, length=6, rate=rate)

        if code == Enum_QoSAttribute.Allocation_Retention_Priority:
            if option is not None:
                arp = cast('Data_AllocationRetentionPriorityAttribute', option)
                level = arp.priority_level
                capability = arp.preemption_capability
                vulnerability = arp.preemption_vulnerability
            else:
                level = cast('int', kwargs.get('priority_level', 1))
                capability = cast('int', kwargs.get('preemption_capability', 0))
                vulnerability = cast('int', kwargs.get('preemption_vulnerability', 0))
            return Schema_AllocationRetentionPriorityAttribute(
                type=code, length=2,
                priority={'PL': level, 'PC': capability, 'PV': vulnerability})

        if code == Enum_QoSAttribute.QoS_Traffic_Selector:
            if option is not None:
                ts_attr = cast('Data_QoSTrafficSelectorAttribute', option)
                ts_format = ts_attr.ts_format  # type: Enum_TrafficSelector | int
                selector = ts_attr.selector
            else:
                ts_format = cast('Enum_TrafficSelector | int',
                                 kwargs.get('ts_format',
                                            Enum_TrafficSelector.IPv6_Binary_Traffic_Selector))
                selector = cast('bytes', kwargs.get('selector', b''))
            return Schema_QoSTrafficSelectorAttribute(
                type=code, length=2 + len(selector),
                ts_format=cast('Enum_TrafficSelector', ts_format), selector=selector)

        if code == Enum_QoSAttribute.QoS_Vendor_Specific_Attribute:
            if option is not None:
                vendor_attr = cast('Data_QoSVendorSpecificAttribute', option)
                vendor, subtype, payload = (vendor_attr.vendor, vendor_attr.subtype,
                                            vendor_attr.data)
            else:
                vendor = cast('int', kwargs.get('vendor', 0))
                subtype = cast('int', kwargs.get('subtype', 0))
                payload = cast('bytes', kwargs.get('data', b''))
            return Schema_QoSVendorSpecificAttribute(
                type=code, length=7 + len(payload), vendor=vendor, subtype=subtype,
                data=payload)

        if option is not None:
            payload = cast('Data_UnassignedQoSAttribute', option).data
        else:
            payload = cast('bytes', kwargs.get('data', b''))
        return Schema_UnassignedQoSAttribute(type=code, length=len(payload), data=payload)

    def _make_opt_qos(self, type: 'Enum_Option', option: 'Optional[Data_QualityOfServiceOption]' = None, *,
                      sr_id: 'int' = 0,
                      dscp: 'int' = 0,
                      oc: 'int' = 0,
                      attributes: 'Optional[QoSAttribute | list[Schema_QoSAttribute | tuple[Enum_QoSAttribute, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_QualityOfServiceOption':
        """Make MH quality-of-service option.

        Args:
            type: Option type.
            option: Option data model.
            sr_id: Service request identifier.
            dscp: Differentiated services code point, 6 bits.
            oc: Operational code.
            attributes: Quality-of-service attributes.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            sr_id = option.sr_id
            dscp = option.dscp
            oc = option.oc
            attributes = option.attributes
        else:
            attributes = attributes or []

        if dscp > 0x3F:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid DSCP: {dscp}')

        entries = self._make_qos_attributes(attributes)
        length = 6 + sum(len(entry) if isinstance(entry, bytes) else len(entry.pack())
                         for entry in entries)

        return Schema_QualityOfServiceOption(
            type=type,
            length=length,
            sr_id=sr_id,
            tc=dscp << 2,
            oc=oc,
            attributes=entries,
        )

    def _make_opt_lma_up(self, type: 'Enum_Option', option: 'Optional[Data_LMAUserPlaneAddressOption]' = None, *,
                         address: 'Optional[bytes | str | int | IPv4Address | IPv6Address]' = None,
                         **kwargs: 'Any') -> 'Schema_LMAUserPlaneAddressOption':
        """Make MH LMA user-plane address option.

        Args:
            type: Option type.
            option: Option data model.
            address: LMA user-plane address, or :obj:`None` to omit it -- which is
                how a mobile access gateway asks for a transport without naming an
                address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            address = option.address

        if address is None:
            return Schema_LMAUserPlaneAddressOption(type=type, length=2, address=b'')

        addr = address if isinstance(
            address, (ipaddress.IPv4Address, ipaddress.IPv6Address)
        ) else ipaddress.ip_address(address)

        return Schema_LMAUserPlaneAddressOption(
            type=type,
            length=6 if addr.version == 4 else 18,
            address=addr,
        )

    def _make_opt_mcast(self, type: 'Enum_Option', option: 'Optional[Data_MulticastMobilityOption]' = None, *,
                        code: 'int' = 2,
                        data: 'bytes' = b'',
                        **kwargs: 'Any') -> 'Schema_MulticastMobilityOption':
        """Make MH multicast mobility option.

        Args:
            type: Option type.
            option: Option data model.
            code: Option code.
            data: MLD or IGMP report payload, opaque to this module.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If the payload is not a whole number of 32-bit words.
                :rfc:`7411#section-5.3` measures this option's length in words, so
                a payload that is not a multiple of 4 octets cannot be described by
                it at all.

        """
        if option is not None:
            code = option.code
            data = option.data

        if len(data) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] payload of {len(data)} octets is '
                                'not a whole number of 32-bit words')

        return Schema_MulticastMobilityOption(
            type=type,
            length=len(data) // 4,
            code=code,
            data=data,
        )

    def _make_opt_mcast_ack(self, type: 'Enum_Option',
                                                       option: 'Optional[Data_MulticastAcknowledgementOption]' = None, *,
                            code: 'int' = 0,
                            status: 'int' = 1,
                            data: 'bytes' = b'',
                            **kwargs: 'Any') -> 'Schema_MulticastAcknowledgementOption':
        """Make MH multicast acknowledgement option.

        Args:
            type: Option type.
            option: Option data model.
            code: Option code; always ``0``.
            status: Status.
            data: MLD or IGMP unsupported report payload, opaque to this module.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If the payload is not a whole number of 32-bit words.

        """
        if option is not None:
            code = option.code
            status = option.status
            data = option.data

        if len(data) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] payload of {len(data)} octets is '
                                'not a whole number of 32-bit words')

        return Schema_MulticastAcknowledgementOption(
            type=type,
            length=len(data) // 4,
            code=code,
            status=status,
            data=data,
        )

    def _make_lcmp_suboptions(
        self,
        suboptions: 'LMAControlledMAGSuboption | list[Schema_LMAControlledMAGSuboption | tuple[Enum_LMAControlledMAGSuboption, dict[str, Any]] | bytes]',
    ) -> 'list[Schema_LMAControlledMAGSuboption | bytes]':
        """Make MH LMA-controlled MAG parameters sub-options.

        Args:
            suboptions: Sub-options, as parsed data, schemas, ``(type, kwargs)``
                pairs, or raw octets.

        Returns:
            Sub-option schema list.

        """
        if isinstance(suboptions, list):
            entries = []  # type: list[Schema_LMAControlledMAGSuboption | bytes]
            for item in suboptions:
                if isinstance(item, (bytes, Schema)):
                    entries.append(cast('Schema_LMAControlledMAGSuboption | bytes', item))
                else:
                    code, args = cast(
                        'tuple[Enum_LMAControlledMAGSuboption, dict[str, Any]]', item)
                    entries.append(self._make_lcmp_suboption(code, **args))
            return entries

        return [self._make_lcmp_suboption(code, option)
                for code, option in suboptions.items(multi=True)]

    @staticmethod
    def _seconds(value: 'int | timedelta', unit: 'int' = 1) -> 'int':
        """Return an interval in wire units.

        Args:
            value: Interval, already in wire units when an :obj:`int`, or as a
                :class:`~datetime.timedelta`.
            unit: Number of seconds one wire unit stands for.

        Returns:
            The interval in wire units.

        """
        if isinstance(value, int):
            return value
        return math.ceil(value.total_seconds() / unit)

    def _make_lcmp_suboption(self, code: 'Enum_LMAControlledMAGSuboption',
                             option: 'Optional[Data_LMAControlledMAGSuboption]' = None,
                             **kwargs: 'Any') -> 'Schema_LMAControlledMAGSuboption':
        """Make one MH LMA-controlled MAG parameters sub-option.

        Args:
            code: Sub-option type.
            option: Sub-option data model.
            **kwargs: Sub-option fields, when no data model is given.

        Returns:
            Constructed sub-option schema.

        Note:
            The data model parameter is named ``option`` rather than ``data`` so
            that it cannot shadow a sub-option field of that name -- see
            :meth:`_make_fid_suboption`, where it did. Dispatch is on ``code``
            rather than on ``isinstance``, for the reason given in
            :meth:`_read_fid_suboptions`.

        """
        if code == Enum_LMAControlledMAGSuboption.Binding_Re_registration_Control:
            if option is not None:
                rereg = cast('Data_BindingReregistrationControlSuboption', option)
                start = math.ceil(rereg.start_time.total_seconds() / 4)
                initial = math.ceil(rereg.initial_retransmission.total_seconds())
                maximum = math.ceil(rereg.max_retransmission.total_seconds())
            else:
                start = self._seconds(kwargs.get('start_time', 0), 4)
                initial = self._seconds(kwargs.get('initial_retransmission', 0))
                maximum = self._seconds(kwargs.get('max_retransmission', 0))
            return Schema_BindingReregistrationControlSuboption(
                type=code, length=6, start_time=start,
                initial_retransmission=initial, max_retransmission=maximum)

        if code == Enum_LMAControlledMAGSuboption.Heartbeat_Control:
            if option is not None:
                heartbeat = cast('Data_HeartbeatControlSuboption', option)
                interval = math.ceil(heartbeat.interval.total_seconds())
                delay = math.ceil(heartbeat.retransmission_delay.total_seconds())
                count = heartbeat.max_retransmissions
            else:
                interval = self._seconds(kwargs.get('interval', 0))
                delay = self._seconds(kwargs.get('retransmission_delay', 0))
                count = cast('int', kwargs.get('max_retransmissions', 0))
            return Schema_HeartbeatControlSuboption(
                type=code, length=6, interval=interval,
                retransmission_delay=delay, max_retransmissions=count)

        if option is not None:
            payload = cast('Data_UnassignedLMAControlledMAGSuboption', option).data
        else:
            payload = cast('bytes', kwargs.get('data', b''))
        return Schema_UnassignedLMAControlledMAGSuboption(
            type=code, length=len(payload), data=payload)

    def _make_opt_lcmp(self, type: 'Enum_Option', option: 'Optional[Data_LMAControlledMAGParametersOption]' = None, *,
                       suboptions: 'Optional[LMAControlledMAGSuboption | list[Schema_LMAControlledMAGSuboption | tuple[Enum_LMAControlledMAGSuboption, dict[str, Any]] | bytes]]' = None,
                       **kwargs: 'Any') -> 'Schema_LMAControlledMAGParametersOption':
        """Make MH LMA-controlled MAG parameters option.

        Args:
            type: Option type.
            option: Option data model.
            suboptions: Sub-options; at least one is required.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            suboptions = option.suboptions
        else:
            suboptions = suboptions or []

        entries = self._make_lcmp_suboptions(suboptions)
        if not entries:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] at least one sub-option is required')

        length = sum(len(entry) if isinstance(entry, bytes) else len(entry.pack())
                     for entry in entries)

        return Schema_LMAControlledMAGParametersOption(
            type=type,
            length=length,
            suboptions=entries,
        )

    def _make_opt_mag_mp(self, type: 'Enum_Option', option: 'Optional[Data_MAGMultipathBindingOption]' = None, *,
                         att: 'Enum_AccessType | StdlibEnum | AenumEnum | str | int' = Enum_AccessType.Virtual,
                         att_default: 'Optional[int]' = None,
                         att_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                         att_reversed: 'bool' = False,
                         label: 'int' = 0,
                         bid: 'int' = 1,
                         bulk: 'bool' = False,
                         overwrite: 'bool' = False,
                         **kwargs: 'Any') -> 'Schema_MAGMultipathBindingOption':
        """Make MH MAG multipath binding option.

        Args:
            type: Option type.
            option: Option data model.
            att: Interface access-technology type.
            att_default: Default access-technology type.
            att_namespace: Access-technology type namespace.
            att_reversed: Reverse access-technology type namespace.
            label: Interface label.
            bid: Binding identifier; ``0`` and ``255`` are reserved.
            bulk: Bulk re-registration flag.
            overwrite: Registration overwrite flag.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If both flags are set, which
                :rfc:`8278#section-4.1` forbids.

        """
        if option is not None:
            att_val = option.att  # type: Enum_AccessType
            label = option.label
            bid = option.bid
            bulk = option.bulk
            overwrite = option.overwrite
        else:
            att_val = self._make_index(att, att_default, namespace=att_namespace,  # type: ignore[assignment]
                                       reversed=att_reversed, pack=False)

        if bulk and overwrite:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] the bulk re-registration and '
                                'registration overwrite flags are mutually exclusive')

        return Schema_MAGMultipathBindingOption(
            type=type,
            length=6,
            att=att_val,
            label=label,
            bid=bid,
            flags={
                'B': int(bulk),
                'O': int(overwrite),
            },
        )

    def _make_opt_mag_id(self, type: 'Enum_Option', option: 'Optional[Data_MAGIdentifierOption]' = None, *,
                         subtype: 'Enum_MNIDSubtype | StdlibEnum | AenumEnum | str | int' = Enum_MNIDSubtype.NAI,
                         subtype_default: 'Optional[int]' = None,
                         subtype_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                         subtype_reversed: 'bool' = False,
                         identifier: 'bytes' = b'',
                         **kwargs: 'Any') -> 'Schema_MAGIdentifierOption':
        """Make MH MAG identifier option.

        Args:
            type: Option type.
            option: Option data model.
            subtype: Sub-type, from the mobile node identifier subtype registry.
            subtype_default: Default sub-type.
            subtype_namespace: Sub-type namespace.
            subtype_reversed: Reverse sub-type namespace.
            identifier: Identifier.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            subtype_val = option.subtype  # type: Enum_MNIDSubtype
            identifier = option.identifier
        else:
            subtype_val = self._make_index(subtype, subtype_default, namespace=subtype_namespace,  # type: ignore[assignment]
                                           reversed=subtype_reversed, pack=False)

        return Schema_MAGIdentifierOption(
            type=type,
            length=2 + len(identifier),
            subtype=subtype_val,
            identifier=identifier,
        )

    def _make_opt_anchored(self, type: 'Enum_Option', option: 'Optional[Data_AnchoredPrefixOption]' = None, *,
                           prefix_length: 'int' = 64,
                           prefix: 'bytes | str | int | IPv6Address' = '::',
                           **kwargs: 'Any') -> 'Schema_AnchoredPrefixOption':
        """Make MH anchored prefix option.

        Args:
            type: Option type.
            option: Option data model.
            prefix_length: Prefix length.
            prefix: Anchored prefix.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            prefix_length = option.prefix_length
            prefix = option.prefix

        if prefix_length > 128:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid prefix length: {prefix_length}')

        return Schema_AnchoredPrefixOption(
            type=type,
            length=18,
            prefix_length=prefix_length,
            prefix=prefix,
        )

    def _make_opt_local_prefix(self, type: 'Enum_Option', option: 'Optional[Data_LocalPrefixOption]' = None, *,
                               prefix_length: 'int' = 64,
                               prefix: 'bytes | str | int | IPv6Address' = '::',
                               **kwargs: 'Any') -> 'Schema_LocalPrefixOption':
        """Make MH local prefix option.

        Args:
            type: Option type.
            option: Option data model.
            prefix_length: Prefix length.
            prefix: Local prefix.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            prefix_length = option.prefix_length
            prefix = option.prefix

        if prefix_length > 128:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid prefix length: {prefix_length}')

        return Schema_LocalPrefixOption(
            type=type,
            length=18,
            prefix_length=prefix_length,
            prefix=prefix,
        )

    def _make_opt_prev_maar(self, type: 'Enum_Option', option: 'Optional[Data_PreviousMAAROption]' = None, *,
                            prefix_length: 'int' = 64,
                            maar: 'bytes | str | int | IPv6Address' = '::',
                            prefix: 'bytes | str | int | IPv6Address' = '::',
                            **kwargs: 'Any') -> 'Schema_PreviousMAAROption':
        """Make MH previous MAAR option.

        Args:
            type: Option type.
            option: Option data model.
            prefix_length: Prefix length of ``prefix``.
            maar: Previous MAAR's global address.
            prefix: Mobile node's home network prefix.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            prefix_length = option.prefix_length
            maar = option.maar
            prefix = option.prefix

        if prefix_length > 128:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid prefix length: {prefix_length}')

        return Schema_PreviousMAAROption(
            type=type,
            length=34,
            prefix_length=prefix_length,
            maar=maar,
            prefix=prefix,
        )

    def _make_opt_serv_maar(self, type: 'Enum_Option', option: 'Optional[Data_ServingMAAROption]' = None, *,
                            address: 'bytes | str | int | IPv6Address' = '::',
                            **kwargs: 'Any') -> 'Schema_ServingMAAROption':
        """Make MH serving MAAR option.

        Args:
            type: Option type.
            option: Option data model.
            address: Serving MAAR's global address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            address = option.address

        return Schema_ServingMAAROption(
            type=type,
            length=16,
            address=address,
        )

    def _make_opt_dlif_lla(self, type: 'Enum_Option', option: 'Optional[Data_DLIFLinkLocalAddressOption]' = None, *,
                           address: 'bytes | str | int | IPv6Address' = '::',
                           **kwargs: 'Any') -> 'Schema_DLIFLinkLocalAddressOption':
        """Make MH DLIF link-local address option.

        Args:
            type: Option type.
            option: Option data model.
            address: Distributed logical interface's link-local address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            address = option.address

        return Schema_DLIFLinkLocalAddressOption(
            type=type,
            length=16,
            address=address,
        )

    def _make_opt_dlif_lladdr(self, type: 'Enum_Option', option: 'Optional[Data_DLIFLinkLayerAddressOption]' = None, *,
                              lla: 'bytes' = b'',
                              **kwargs: 'Any') -> 'Schema_DLIFLinkLayerAddressOption':
        """Make MH DLIF link-layer address option.

        Args:
            type: Option type.
            option: Option data model.
            lla: Distributed logical interface's link-layer address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            lla = option.lla

        return Schema_DLIFLinkLayerAddressOption(
            type=type,
            length=2 + len(lla),
            lla=lla,
        )

    def _make_cga_extensions(self, extensions: 'Extension | list[Schema_CGAExtension | tuple[Enum_CGAExtension, dict[str, Any]] | bytes]') -> 'tuple[list[Schema_CGAExtension | bytes], int]':
        """Make CGA extensions for MH.

        Args:
            extensions: CGA extensions.

        Returns:
            Tuple of extensions and total length of extensions.

        """
        total_length = 0
        if isinstance(extensions, list):
            extensions_list = []  # type: list[Schema_CGAExtension | bytes]
            for schema in extensions:
                if isinstance(schema, bytes):
                    code = Enum_CGAExtension.get(int.from_bytes(schema[0:2], 'big', signed=False))

                    data = schema  # type: Schema_CGAExtension | bytes
                    data_len = len(data)
                elif isinstance(schema, Schema):
                    data = schema
                    data_len = len(schema.pack())
                else:
                    code, args = cast('tuple[Enum_CGAExtension, dict[str, Any]]', schema)
                    name = self._lookup_registry(self.__extension__, code)
                    if isinstance(name, str):
                        meth_name = f'_make_ext_{name}'
                        meth = cast('ExtensionConstructor',
                                    getattr(self, meth_name, self._make_ext_none))
                    else:
                        meth = name[1]

                    data = meth(code, **args)
                    data_len = len(data.pack())

                extensions_list.append(data)
                total_length += data_len
            return extensions_list, total_length

        extensions_list = []
        for code, extension in extensions.items(multi=True):
            name = self._lookup_registry(self.__extension__, code)
            if isinstance(name, str):
                meth_name = f'_make_ext_{name}'
                meth = cast('ExtensionConstructor',
                            getattr(self, meth_name, self._make_ext_none))
            else:
                meth = name[1]

            data = meth(code, extension)
            data_len = len(data.pack())

            extensions_list.append(data)
            total_length += data_len
        return extensions_list, total_length

    def _make_ext_none(self, type: 'Enum_CGAExtension', option: 'Optional[Data_UnknownExtension]' = None, *,
                       data: 'bytes' = b'',
                       **kwargs: 'Any') -> 'Schema_UnknownExtension':
        """Make CGA extension.

        Args:
            type: Extension type.
            option: Extension data model.
            data: Extension data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed extension schema.

        """
        if option is not None:
            data = option.data

        return Schema_UnknownExtension(
            type=type,
            length=len(data),
            data=data,
        )

    def _make_ext_multiprefix(self, type: 'Enum_CGAExtension', option: 'Optional[Data_MultiPrefixExtension]' = None, *,
                              flag: 'bool' = False,
                              prefixes: 'Optional[list[int]]' = None,
                              **kwargs: 'Any') -> 'Schema_MultiPrefixExtension':
        """Make CGA multi-prefix extension.

        Args:
            type: Extension type.
            option: Extension data model.
            flag: Public key flag.
            prefixes: Prefixes.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed extension schema.

        """
        if option is not None:
            flag = option.flag
            # NOTE: ``list()`` rather than a cast: the data model stores the
            # prefixes as a :obj:`tuple`, which
            # :class:`~pcapkit.corekit.fields.collections.ListField` refuses to
            # pack -- it raises ``ProtocolUnbound: unsupported type <class
            # 'tuple'>``. The cast this replaced was a no-op at runtime, so
            # re-making a parsed Multi-Prefix extension could not work at all.
            prefixes = list(option.prefixes)
        else:
            prefixes = prefixes or []

        return Schema_MultiPrefixExtension(
            type=type,
            # NOTE: The extension data is the 4-octet flags word followed by one
            # **8**-octet prefix apiece, since
            # :attr:`~pcapkit.protocols.schema.internet.mh.MultiPrefixExtension.prefixes`
            # is a list of :class:`~pcapkit.corekit.fields.numbers.UInt64Field`.
            # This used to read ``1 + len(prefixes) * 16``, which declared 33
            # octets where 20 were emitted for two prefixes, so a re-parse ran off
            # the end of the extension.
            length=4 + len(prefixes) * 8,
            flags={
                'P': int(flag),
            },
            prefixes=prefixes,
        )

    def _make_ext_exp(self, type: 'Enum_CGAExtension', option: 'Optional[Data_ExperimentalExtension]' = None, *,
                      data: 'bytes' = b'',
                      **kwargs: 'Any') -> 'Schema_ExperimentalExtension':
        """Make experimental CGA extension.

        Args:
            type: Extension type.
            option: Extension data model.
            data: Extension data, which :rfc:`4581#section-3` gives no structure.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed extension schema.

        """
        if option is not None:
            data = option.data

        return Schema_ExperimentalExtension(
            type=type,
            length=len(data),
            data=data,
        )
