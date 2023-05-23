# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.mh.MH` Constant Enumerations
======================================================================

.. module:: pcapkit.const.mh

This module contains all constant enumerations of
:class:`~pcapkit.protocols.internet.mh.MH` implementations. Available
enumerations include:

.. list-table::

   * - :class:`MH_Packet <pcapkit.const.mh.packet.Packet>`
     - Mobility Header Types [*]_
   * - :class:`MH_Option <pcapkit.const.mh.option.Option>`
     - Mobility Options [*]_
   * - :class:`MH_DNSStatusCode <pcapkit.const.mh.dns_status_code.DNSStatusCode>`
     - Status Codes (DNS Update Mobility Option) [*]_
   * - :class:`MH_ACKStatusCode <pcapkit.const.mh.ack_status_code.ACKStatusCode>`
     - Pseudo Home Address Acknowledgement Status Codes [*]_
   * - :class:`MH_MNIDSubtype <pcapkit.const.mh.mn_id_subtype.MNIDSubtype>`
     - Mobile Node Identifier Option Subtypes [*]_
   * - :class:`MH_StatusCode <pcapkit.const.mh.status_code.StatusCode>`
     - Status Codes [*]_
   * - :class:`MH_EnumeratingAlgorithm <pcapkit.const.mh.enumerating_algorithm.EnumeratingAlgorithm>`
     - Enumerating Algorithms [*]_
   * - :class:`MH_AuthSubtype <pcapkit.const.mh.auth_subtype.AuthSubtype>`
     - Subtype Field of the MN-HA and MN-AAA Authentication Mobility Options [*]_
   * - :class:`MH_HandoffType <pcapkit.const.mh.handoff_type.HandoffType>`
     - Handoff Indicator Option Type Values [*]_
   * - :class:`MH_AccessType <pcapkit.const.mh.access_type.AccessType>`
     - Access Technology Type Option Type Values [*]_
   * - :class:`MH_BindingUpdateFlag <pcapkit.const.mh.binding_update_flag.BindingUpdateFlag>`
     - Binding Update Flags [*]_
   * - :class:`MH_BindingACKFlag <pcapkit.const.mh.binding_ack_flag.BindingACKFlag>`
     - Binding Acknowledgment Flags [*]_
   * - :class:`MH_DSMIPv6HomeAddress <pcapkit.const.mh.dsmipv6_home_address.DSMIPv6HomeAddress>`
     - Dual Stack MIPv6 (DSMIPv6) IPv4 Home Address Option Status Codes [*]_
   * - :class:`MH_BindingRevocation <pcapkit.const.mh.binding_revocation.BindingRevocation>`
     - Binding Revocation Type [*]_
   * - :class:`MH_RevocationTrigger <pcapkit.const.mh.revocation_trigger.RevocationTrigger>`
     - Revocation Trigger Values [*]_
   * - :class:`MH_RevocationStatusCode <pcapkit.const.mh.revocation_status_code.RevocationStatusCode>`
     - Binding Revocation Acknowledgement Status Codes [*]_
   * - :class:`MH_HomeAddressReply <pcapkit.const.mh.home_address_reply.HomeAddressReply>`
     - IPv4 Home Address Reply Status Codes [*]_
   * - :class:`MH_DHCPSupportMode <pcapkit.const.mh.dhcp_support_mode.DHCPSupportMode>`
     - IPv4 DHCP Support Mode Flags [*]_
   * - :class:`MH_HandoverInitiateFlag <pcapkit.const.mh.handover_initiate_flag.HandoverInitiateFlag>`
     - Handover Initiate Flags [*]_
   * - :class:`MH_HandoverACKFlag <pcapkit.const.mh.handover_ack_flag.HandoverACKFlag>`
     - Handover Acknowledge Flags [*]_
   * - :class:`MH_HandoverACKStatus <pcapkit.const.mh.handover_ack_status.HandoverACKStatus>`
     - Handover Initiate Status Codes [*]_
   * - :class:`MH_HandoverACKStatus <pcapkit.const.mh.handover_ack_status.HandoverACKStatus>`
     - Handover Acknowledge Status Codes [*]_
   * - :class:`MH_FlowIDStatus <pcapkit.const.mh.flow_id_status.FlowIDStatus>`
     - Flow Identification Mobility Option Status Codes [*]_
   * - :class:`MH_FlowIDSuboption <pcapkit.const.mh.flow_id_suboption.FlowIDSuboption>`
     - Flow Identification Sub-Options [*]_
   * - :class:`MH_TrafficSelector <pcapkit.const.mh.traffic_selector.TrafficSelector>`
     - Traffic Selector Format [*]_
   * - :class:`MH_MNGroupID <pcapkit.const.mh.mn_group_id.MNGroupID>`
     - Mobile Node Group Identifier Type Registry [*]_
   * - :class:`MH_DSMIP6TLSPacket <pcapkit.const.mh.dsmip6_tls_packet.DSMIP6TLSPacket>`
     - DSMIP6-TLS Packet Types Registry [*]_
   * - :class:`MH_ANISuboption <pcapkit.const.mh.ani_suboption.ANISuboption>`
     - Access Network Information (ANI) Sub-Option Type Values [*]_
   * - :class:`MH_OperatorID <pcapkit.const.mh.operator_id.OperatorID>`
     - Operator-Identifier Type Registry [*]_
   * - :class:`MH_UpdateNotificationReason <pcapkit.const.mh.upn_reason.UpdateNotificationReason>`
     - Update Notification Reasons Registry [*]_
   * - :class:`MH_UpdateNotificationACKStatus <pcapkit.const.mh.upa_status.UpdateNotificationACKStatus>`
     - Update Notification Acknowledgement Status Registry [*]_
   * - :class:`MH_FlowBindingType <pcapkit.const.mh.fb_type.FlowBindingType>`
     - Flow Binding Type [*]_
   * - :class:`MH_FlowBindingIndicationTrigger <pcapkit.const.mh.fb_indication_trigger.FlowBindingIndicationTrigger>`
     - Flow Binding Indication Triggers [*]_
   * - :class:`MH_FlowBindingACKStatus <pcapkit.const.mh.fb_ack_status.FlowBindingACKStatus>`
     - Flow Binding Acknowledgement Status Codes [*]_
   * - :class:`MH_FlowBindingAction <pcapkit.const.mh.fb_action.FlowBindingAction>`
     - Flow Binding Action Values [*]_
   * - :class:`MH_QoSAttribute <pcapkit.const.mh.qos_attribute.QoSAttribute>`
     - Quality-of-Service Attribute Registry [*]_
   * - :class:`MH_LMAControlledMAGSuboption <pcapkit.const.mh.lma_mag_suboption.LMAControlledMAGSuboption>`
     - LMA-Controlled MAG Parameters Sub-Option Type Values [*]_
   * - :class:`MH_LLACode <pcapkit.const.mh.lla_code.LLACode>`
     - Link-Layer Address (LLA) Option Code [*]_
   * - :class:`MH_CGAType <pcapkit.const.mh.cga_type.CGAType>`
     - CGA Extension Type Tags [*]_
   * - :class:`MH_CGAExtension <pcapkit.const.mh.cga_type.CGAExtension>`
     - CGA Extension Type Values [*]_
   * - :class:`MH_CGASec <pcapkit.const.mh.cga_sec.CGASec>`
     - CGA SEC [*]_
   * - :class:`MH_BindingError <pcapkit.const.mh.binding_error.BindingError>`
     - Bingding Error Status Code [*]_

.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-1
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-2
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-3
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-4
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-5
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-6
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-7
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-8
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-9
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-10
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-11
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-12
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#dsmipv6-home-address-option
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#binding-revocation-type
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#revocation-trigger-values
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#binding-revocation-status-codes
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#home-address-reply
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#dhcp-support-mode
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#handover-initiate-flags
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#handover-acknowledge-flags
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#handover-initiate-status
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#handover-acknowledge-status
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#flow-id
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#flow-id-suboptions
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#traffic-selector
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobile-node-group-id-type
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#dsmip6-tls-packet-types
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#ani
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#op-id
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#upn-reasons
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#upa-status
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#flow-binding-type
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#flow-binding-indication-triggers
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#flow-binding-ack-status
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#flow-binding-action
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#qos-attribute
.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#lma-controlled-mag-parameters-sub-option-type
.. [*] :rfc:`5568#section-6.4.3`
.. [*] https://www.iana.org/assignments/cga-message-types/cga-message-types.xhtml#cga-message-types-1
.. [*] https://www.iana.org/assignments/cga-message-types/cga-message-types.xhtml#cga-message-types-2
.. [*] https://www.iana.org/assignments/cga-message-types/cga-message-types.xhtml#cga-message-types-3
.. [*] :rfc:`6275#section-6.1.9`

"""

from pcapkit.const.mh.access_type import AccessType as MH_AccessType
from pcapkit.const.mh.ack_status_code import ACKStatusCode as MH_ACKStatusCode
from pcapkit.const.mh.ani_suboption import ANISuboption as MH_ANISuboption
from pcapkit.const.mh.auth_subtype import AuthSubtype as MH_AuthSubtype
from pcapkit.const.mh.binding_ack_flag import BindingACKFlag as MH_BindingACKFlag
from pcapkit.const.mh.binding_error import BindingError as MH_BindingError
from pcapkit.const.mh.binding_revocation import BindingRevocation as MH_BindingRevocation
from pcapkit.const.mh.binding_update_flag import BindingUpdateFlag as MH_BindingUpdateFlag
from pcapkit.const.mh.cga_extension import CGAExtension as MH_CGAExtension
from pcapkit.const.mh.cga_sec import CGASec as MH_CGASec
from pcapkit.const.mh.cga_type import CGAType as MH_CGAType
from pcapkit.const.mh.dhcp_support_mode import DHCPSupportMode as MH_DHCPSupportMode
from pcapkit.const.mh.dns_status_code import DNSStatusCode as MH_DNSStatusCode
from pcapkit.const.mh.dsmip6_tls_packet import DSMIP6TLSPacket as MH_DSMIP6TLSPacket
from pcapkit.const.mh.dsmipv6_home_address import DSMIPv6HomeAddress as MH_DSMIPv6HomeAddress
from pcapkit.const.mh.enumerating_algorithm import EnumeratingAlgorithm as MH_EnumeratingAlgorithm
from pcapkit.const.mh.fb_ack_status import FlowBindingACKStatus as MH_FlowBindingACKStatus
from pcapkit.const.mh.fb_action import FlowBindingAction as MH_FlowBindingAction
from pcapkit.const.mh.fb_indication_trigger import \
    FlowBindingIndicationTrigger as MH_FlowBindingIndicationTrigger
from pcapkit.const.mh.fb_type import FlowBindingType as MH_FlowBindingType
from pcapkit.const.mh.flow_id_status import FlowIDStatus as MH_FlowIDStatus
from pcapkit.const.mh.flow_id_suboption import FlowIDSuboption as MH_FlowIDSuboption
from pcapkit.const.mh.handoff_type import HandoffType as MH_HandoffType
from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag as MH_HandoverACKFlag
from pcapkit.const.mh.handover_ack_status import HandoverACKStatus as MH_HandoverACKStatus
from pcapkit.const.mh.handover_initiate_flag import HandoverInitiateFlag as MH_HandoverInitiateFlag
from pcapkit.const.mh.home_address_reply import HomeAddressReply as MH_HomeAddressReply
from pcapkit.const.mh.lla_code import LLACode as MH_LLACode
from pcapkit.const.mh.lma_mag_suboption import \
    LMAControlledMAGSuboption as MH_LMAControlledMAGSuboption
from pcapkit.const.mh.mn_group_id import MNGroupID as MH_MNGroupID
from pcapkit.const.mh.mn_id_subtype import MNIDSubtype as MH_MNIDSubtype
from pcapkit.const.mh.operator_id import OperatorID as MH_OperatorID
from pcapkit.const.mh.option import Option as MH_Option
from pcapkit.const.mh.packet import Packet as MH_Packet
from pcapkit.const.mh.qos_attribute import QoSAttribute as MH_QoSAttribute
from pcapkit.const.mh.revocation_status_code import RevocationStatusCode as MH_RevocationStatusCode
from pcapkit.const.mh.revocation_trigger import RevocationTrigger as MH_RevocationTrigger
from pcapkit.const.mh.status_code import StatusCode as MH_StatusCode
from pcapkit.const.mh.traffic_selector import TrafficSelector as MH_TrafficSelector
from pcapkit.const.mh.upa_status import \
    UpdateNotificationACKStatus as MH_UpdateNotificationACKStatus
from pcapkit.const.mh.upn_reason import UpdateNotificationReason as MH_UpdateNotificationReason

__all__ = [
    'MH_Packet', 'MH_Option', 'MH_DNSStatusCode', 'MH_ACKStatusCode',
    'MH_MNIDSubtype', 'MH_StatusCode', 'MH_EnumeratingAlgorithm',
    'MH_AuthSubtype', 'MH_HandoffType', 'MH_AccessType',
    'MH_BindingUpdateFlag', 'MH_BindingACKFlag', 'MH_DSMIPv6HomeAddress',
    'MH_BindingRevocation', 'MH_RevocationTrigger', 'MH_RevocationStatusCode',
    'MH_HomeAddressReply', 'MH_DHCPSupportMode', 'MH_HandoverInitiateFlag',
    'MH_HandoverACKFlag', 'MH_HandoverACKStatus', 'MH_HandoverACKStatus',
    'MH_FlowIDStatus', 'MH_FlowIDSuboption', 'MH_TrafficSelector',
    'MH_MNGroupID', 'MH_DSMIP6TLSPacket', 'MH_ANISuboption', 'MH_OperatorID',
    'MH_UpdateNotificationReason', 'MH_UpdateNotificationACKStatus',
    'MH_FlowBindingType', 'MH_FlowBindingIndicationTrigger',
    'MH_FlowBindingACKStatus', 'MH_FlowBindingAction', 'MH_QoSAttribute',
    'MH_LMAControlledMAGSuboption', 'MH_LLACode', 'MH_CGAType',
    'MH_CGAExtension', 'MH_CGASec', 'MH_BindingError',
]
