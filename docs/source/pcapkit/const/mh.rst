================================================================
:class:`~pcapkit.protocols.internet.mh.MH` Constant Enumerations
================================================================

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

Access Technology Type Option Type Values
=========================================

.. module:: pcapkit.const.mh.access_type

This module contains the constant enumeration for **Access Technology Type Option Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.access_type.AccessType`.

.. autoclass:: pcapkit.const.mh.access_type.AccessType
   :members:
   :undoc-members:
   :show-inheritance:

Pseudo Home Address Acknowledgement Status Codes
================================================

.. module:: pcapkit.const.mh.ack_status_code

This module contains the constant enumeration for **Pseudo Home Address Acknowledgement Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.ack_status_code.ACKStatusCode`.

.. autoclass:: pcapkit.const.mh.ack_status_code.ACKStatusCode
   :members:
   :undoc-members:
   :show-inheritance:

Access Network Information (ANI) Sub-Option Type Values
=======================================================

.. module:: pcapkit.const.mh.ani_suboption

This module contains the constant enumeration for **Access Network Information (ANI) Sub-Option Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.ani_suboption.ANISuboption`.

.. autoclass:: pcapkit.const.mh.ani_suboption.ANISuboption
   :members:
   :undoc-members:
   :show-inheritance:

Subtype Field of the MN-HA and MN-AAA Authentication Mobility Options
=====================================================================

.. module:: pcapkit.const.mh.auth_subtype

This module contains the constant enumeration for **Subtype Field of the MN-HA and MN-AAA Authentication Mobility Options**,
which is automatically generated from :class:`pcapkit.vendor.mh.auth_subtype.AuthSubtype`.

.. autoclass:: pcapkit.const.mh.auth_subtype.AuthSubtype
   :members:
   :undoc-members:
   :show-inheritance:

Binding Acknowledgment Flags
============================

.. module:: pcapkit.const.mh.binding_ack_flag

This module contains the constant enumeration for **Binding Acknowledgment Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.binding_ack_flag.BindingACKFlag`.

.. autoclass:: pcapkit.const.mh.binding_ack_flag.BindingACKFlag
   :members:
   :undoc-members:
   :show-inheritance:

Binding Revocation Type
=======================

.. module:: pcapkit.const.mh.binding_revocation

This module contains the constant enumeration for **Binding Revocation Type**,
which is automatically generated from :class:`pcapkit.vendor.mh.binding_revocation.BindingRevocation`.

.. autoclass:: pcapkit.const.mh.binding_revocation.BindingRevocation
   :members:
   :undoc-members:
   :show-inheritance:

Binding Update Flags
====================

.. module:: pcapkit.const.mh.binding_update_flag

This module contains the constant enumeration for **Binding Update Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.binding_update_flag.BindingUpdateFlag`.

.. autoclass:: pcapkit.const.mh.binding_update_flag.BindingUpdateFlag
   :members:
   :undoc-members:
   :show-inheritance:

IPv4 DHCP Support Mode Flags
============================

.. module:: pcapkit.const.mh.dhcp_support_mode

This module contains the constant enumeration for **IPv4 DHCP Support Mode Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.dhcp_support_mode.DHCPSupportMode`.

.. autoclass:: pcapkit.const.mh.dhcp_support_mode.DHCPSupportMode
   :members:
   :undoc-members:
   :show-inheritance:

Status Codes (DNS Update Mobility Option)
=========================================

.. module:: pcapkit.const.mh.dns_status_code

This module contains the constant enumeration for **Status Codes (DNS Update Mobility Option)**,
which is automatically generated from :class:`pcapkit.vendor.mh.dns_status_code.DNSStatusCode`.

.. autoclass:: pcapkit.const.mh.dns_status_code.DNSStatusCode
   :members:
   :undoc-members:
   :show-inheritance:

DSMIP6-TLS Packet Types Registry
================================

.. module:: pcapkit.const.mh.dsmip6_tls_packet

This module contains the constant enumeration for **DSMIP6-TLS Packet Types Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.dsmip6_tls_packet.DSMIP6TLSPacket`.

.. autoclass:: pcapkit.const.mh.dsmip6_tls_packet.DSMIP6TLSPacket
   :members:
   :undoc-members:
   :show-inheritance:

Dual Stack MIPv6 (DSMIPv6) IPv4 Home Address Option Status Codes
================================================================

.. module:: pcapkit.const.mh.dsmipv6_home_address

This module contains the constant enumeration for **Dual Stack MIPv6 (DSMIPv6) IPv4 Home Address Option Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.dsmipv6_home_address.DSMIPv6HomeAddress`.

.. autoclass:: pcapkit.const.mh.dsmipv6_home_address.DSMIPv6HomeAddress
   :members:
   :undoc-members:
   :show-inheritance:

Enumerating Algorithms
======================

.. module:: pcapkit.const.mh.enumerating_algorithm

This module contains the constant enumeration for **Enumerating Algorithms**,
which is automatically generated from :class:`pcapkit.vendor.mh.enumerating_algorithm.EnumeratingAlgorithm`.

.. autoclass:: pcapkit.const.mh.enumerating_algorithm.EnumeratingAlgorithm
   :members:
   :undoc-members:
   :show-inheritance:

Flow Binding Acknowledgement Status Codes
=========================================

.. module:: pcapkit.const.mh.fb_ack_status

This module contains the constant enumeration for **Flow Binding Acknowledgement Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.fb_ack_status.FlowBindingACKStatus`.

.. autoclass:: pcapkit.const.mh.fb_ack_status.FlowBindingACKStatus
   :members:
   :undoc-members:
   :show-inheritance:

Flow Binding Action Values
==========================

.. module:: pcapkit.const.mh.fb_action

This module contains the constant enumeration for **Flow Binding Action Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.fb_action.FlowBindingAction`.

.. autoclass:: pcapkit.const.mh.fb_action.FlowBindingAction
   :members:
   :undoc-members:
   :show-inheritance:

Flow Binding Indication Triggers
================================

.. module:: pcapkit.const.mh.fb_indication_trigger

This module contains the constant enumeration for **Flow Binding Indication Triggers**,
which is automatically generated from :class:`pcapkit.vendor.mh.fb_indication_trigger.FlowBindingIndicationTrigger`.

.. autoclass:: pcapkit.const.mh.fb_indication_trigger.FlowBindingIndicationTrigger
   :members:
   :undoc-members:
   :show-inheritance:

Flow Binding Type
=================

.. module:: pcapkit.const.mh.fb_type

This module contains the constant enumeration for **Flow Binding Type**,
which is automatically generated from :class:`pcapkit.vendor.mh.fb_type.FlowBindingType`.

.. autoclass:: pcapkit.const.mh.fb_type.FlowBindingType
   :members:
   :undoc-members:
   :show-inheritance:

Flow Identification Mobility Option Status Codes
================================================

.. module:: pcapkit.const.mh.flow_id_status

This module contains the constant enumeration for **Flow Identification Mobility Option Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.flow_id_status.FlowIDStatus`.

.. autoclass:: pcapkit.const.mh.flow_id_status.FlowIDStatus
   :members:
   :undoc-members:
   :show-inheritance:

Flow Identification Sub-Options
===============================

.. module:: pcapkit.const.mh.flow_id_suboption

This module contains the constant enumeration for **Flow Identification Sub-Options**,
which is automatically generated from :class:`pcapkit.vendor.mh.flow_id_suboption.FlowIDSuboption`.

.. autoclass:: pcapkit.const.mh.flow_id_suboption.FlowIDSuboption
   :members:
   :undoc-members:
   :show-inheritance:

Handoff Indicator Option Type Values
====================================

.. module:: pcapkit.const.mh.handoff_type

This module contains the constant enumeration for **Handoff Indicator Option Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.handoff_type.HandoffType`.

.. autoclass:: pcapkit.const.mh.handoff_type.HandoffType
   :members:
   :undoc-members:
   :show-inheritance:

Handover Acknowledge Flags
==========================

.. module:: pcapkit.const.mh.handover_ack_flag

This module contains the constant enumeration for **Handover Acknowledge Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.handover_ack_flag.HandoverACKFlag`.

.. autoclass:: pcapkit.const.mh.handover_ack_flag.HandoverACKFlag
   :members:
   :undoc-members:
   :show-inheritance:

Handover Acknowledge Status Codes
=================================

.. module:: pcapkit.const.mh.handover_ack_status

This module contains the constant enumeration for **Handover Acknowledge Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.handover_ack_status.HandoverACKStatus`.

.. autoclass:: pcapkit.const.mh.handover_ack_status.HandoverACKStatus
   :members:
   :undoc-members:
   :show-inheritance:

Handover Initiate Flags
=======================

.. module:: pcapkit.const.mh.handover_initiate_flag

This module contains the constant enumeration for **Handover Initiate Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.handover_initiate_flag.HandoverInitiateFlag`.

.. autoclass:: pcapkit.const.mh.handover_initiate_flag.HandoverInitiateFlag
   :members:
   :undoc-members:
   :show-inheritance:

Handover Initiate Status Codes
==============================

.. module:: pcapkit.const.mh.handover_initiate_status

This module contains the constant enumeration for **Handover Initiate Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.handover_initiate_status.HandoverInitiateStatus`.

.. autoclass:: pcapkit.const.mh.handover_initiate_status.HandoverInitiateStatus
   :members:
   :undoc-members:
   :show-inheritance:

IPv4 Home Address Reply Status Codes
====================================

.. module:: pcapkit.const.mh.home_address_reply

This module contains the constant enumeration for **IPv4 Home Address Reply Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.home_address_reply.HomeAddressReply`.

.. autoclass:: pcapkit.const.mh.home_address_reply.HomeAddressReply
   :members:
   :undoc-members:
   :show-inheritance:

LMA-Controlled MAG Parameters Sub-Option Type Values
====================================================

.. module:: pcapkit.const.mh.lma_mag_suboption

This module contains the constant enumeration for **LMA-Controlled MAG Parameters Sub-Option Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.lma_mag_suboption.LMAControlledMAGSuboption`.

.. autoclass:: pcapkit.const.mh.lma_mag_suboption.LMAControlledMAGSuboption
   :members:
   :undoc-members:
   :show-inheritance:

Mobile Node Group Identifier Type Registry
==========================================

.. module:: pcapkit.const.mh.mn_group_id

This module contains the constant enumeration for **Mobile Node Group Identifier Type Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.mn_group_id.MNGroupID`.

.. autoclass:: pcapkit.const.mh.mn_group_id.MNGroupID
   :members:
   :undoc-members:
   :show-inheritance:

Mobile Node Identifier Option Subtypes
======================================

.. module:: pcapkit.const.mh.mn_id_subtype

This module contains the constant enumeration for **Mobile Node Identifier Option Subtypes**,
which is automatically generated from :class:`pcapkit.vendor.mh.mn_id_subtype.MNIDSubtype`.

.. autoclass:: pcapkit.const.mh.mn_id_subtype.MNIDSubtype
   :members:
   :undoc-members:
   :show-inheritance:

Operator-Identifier Type Registry
=================================

.. module:: pcapkit.const.mh.operator_id

This module contains the constant enumeration for **Operator-Identifier Type Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.operator_id.OperatorID`.

.. autoclass:: pcapkit.const.mh.operator_id.OperatorID
   :members:
   :undoc-members:
   :show-inheritance:

Mobility Options
================

.. module:: pcapkit.const.mh.option

This module contains the constant enumeration for **Mobility Options**,
which is automatically generated from :class:`pcapkit.vendor.mh.option.Option`.

.. autoclass:: pcapkit.const.mh.option.Option
   :members:
   :undoc-members:
   :show-inheritance:

Mobility Header Types - for the MH Type field in the Mobility Header
====================================================================

.. module:: pcapkit.const.mh.packet

This module contains the constant enumeration for **Mobility Header Types - for the MH Type field in the Mobility Header**,
which is automatically generated from :class:`pcapkit.vendor.mh.packet.Packet`.

.. autoclass:: pcapkit.const.mh.packet.Packet
   :members:
   :undoc-members:
   :show-inheritance:

Quality-of-Service Attribute Registry
=====================================

.. module:: pcapkit.const.mh.qos_attribute

This module contains the constant enumeration for **Quality-of-Service Attribute Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.qos_attribute.QoSAttribute`.

.. autoclass:: pcapkit.const.mh.qos_attribute.QoSAttribute
   :members:
   :undoc-members:
   :show-inheritance:

Binding Revocation Acknowledgement Status Codes
===============================================

.. module:: pcapkit.const.mh.revocation_status_code

This module contains the constant enumeration for **Binding Revocation Acknowledgement Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.revocation_status_code.RevocationStatusCode`.

.. autoclass:: pcapkit.const.mh.revocation_status_code.RevocationStatusCode
   :members:
   :undoc-members:
   :show-inheritance:

Revocation Trigger Values
=========================

.. module:: pcapkit.const.mh.revocation_trigger

This module contains the constant enumeration for **Revocation Trigger Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.revocation_trigger.RevocationTrigger`.

.. autoclass:: pcapkit.const.mh.revocation_trigger.RevocationTrigger
   :members:
   :undoc-members:
   :show-inheritance:

Status Codes
============

.. module:: pcapkit.const.mh.status_code

This module contains the constant enumeration for **Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.status_code.StatusCode`.

.. autoclass:: pcapkit.const.mh.status_code.StatusCode
   :members:
   :undoc-members:
   :show-inheritance:

Traffic Selector Format
=======================

.. module:: pcapkit.const.mh.traffic_selector

This module contains the constant enumeration for **Traffic Selector Format**,
which is automatically generated from :class:`pcapkit.vendor.mh.traffic_selector.TrafficSelector`.

.. autoclass:: pcapkit.const.mh.traffic_selector.TrafficSelector
   :members:
   :undoc-members:
   :show-inheritance:

Update Notification Acknowledgement Status Registry
===================================================

.. module:: pcapkit.const.mh.upa_status

This module contains the constant enumeration for **Update Notification Acknowledgement Status Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.upa_status.UpdateNotificationACKStatus`.

.. autoclass:: pcapkit.const.mh.upa_status.UpdateNotificationACKStatus
   :members:
   :undoc-members:
   :show-inheritance:

Update Notification Reasons Registry
====================================

.. module:: pcapkit.const.mh.upn_reason

This module contains the constant enumeration for **Update Notification Reasons Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.upn_reason.UpdateNotificationReason`.

.. autoclass:: pcapkit.const.mh.upn_reason.UpdateNotificationReason
   :members:
   :undoc-members:
   :show-inheritance:

Link-Layer Address (LLA) Option Code
====================================

.. module:: pcapkit.const.mh.lla_code

This module contains the constant enumeration for **Link-Layer Address (LLA) Option Code**,
which is automatically generated from :class:`pcapkit.vendor.mh.lla_code.LLACode`.

.. autoclass:: pcapkit.const.mh.lla_code.LLACode
   :members:
   :undoc-members:
   :show-inheritance:

CGA Extension Type Tags
=======================

.. module:: pcapkit.const.mh.cga_type

This module contains the constant enumeration for **CGA Extension Type Tags**,
which is automatically generated from :class:`pcapkit.vendor.mh.cga_type.CGAType`.

.. autoclass:: pcapkit.const.mh.cga_type.CGAType
   :members:
   :undoc-members:
   :show-inheritance:

CGA Extension Type Values
===============================

.. module:: pcapkit.const.mh.cga_extension

This module contains the constant enumeration for **CGA Extension Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.cga_extension.CGAExtension`.

.. autoclass:: pcapkit.const.mh.cga_extension.CGAExtension
   :members:
   :undoc-members:
   :show-inheritance:

CGA SEC
=======

.. module:: pcapkit.const.mh.cga_sec

This module contains the constant enumeration for **CGA SEC**,
which is automatically generated from :class:`pcapkit.vendor.mh.cga_sec.CGASec`.

.. autoclass:: pcapkit.const.mh.cga_sec.CGASec
   :members:
   :undoc-members:
   :show-inheritance:

Binding Error Status Code
=========================

.. module:: pcapkit.const.mh.binding_error

This module contains the constant enumeration for **Binding Error Status Code**,
which is automatically generated from :class:`pcapkit.vendor.mh.binding_error.BindingError`.

.. autoclass:: pcapkit.const.mh.binding_error.BindingError
   :members:
   :undoc-members:
   :show-inheritance:

.. raw:: html

   <hr />

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
