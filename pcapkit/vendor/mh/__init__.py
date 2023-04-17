# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.mh.MH` Vendor Crawlers
================================================================

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.mh.MH` implementations. Available
enumerations include:

.. list-table::

   * - :class:`MH_Packet <pcapkit.vendor.mh.packet.Packet>`
     - Mobility Header Types [*]_
   * - :class:`MH_Option <pcapkit.vendor.mh.option.Option>`
     - Mobility Options [*]_
   * - :class:`MH_DNSStatusCode <pcapkit.vendor.mh.dns_status_code.DNSStatusCode>`
     - Status Codes (DNS Update Mobility Option) [*]_
   * - :class:`MH_ACKStatusCode <pcapkit.vendor.mh.ack_status_code.ACKStatusCode>`
     - Pseudo Home Address Acknowledgement Status Codes [*]_
   * - :class:`MH_MNIDSubtype <pcapkit.vendor.mh.mn_id_subtype.MNIDSubtype>`
     - Mobile Node Identifier Option Subtypes [*]_
   * - :class:`MH_StatusCode <pcapkit.vendor.mh.status_code.StatusCode>`
     - Status Codes [*]_
   * - :class:`MH_EnumeratingAlgorithm <pcapkit.vendor.mh.enumerating_algorithm.EnumeratingAlgorithm>`
     - Enumerating Algorithms [*]_
   * - :class:`MH_AuthSubtype <pcapkit.vendor.mh.auth_subtype.AuthSubtype>`
     - Subtype Field of the MN-HA and MN-AAA Authentication Mobility Options [*]_
   * - :class:`MH_HandoffType <pcapkit.vendor.mh.handoff_type.HandoffType>`
     - Handoff Indicator Option Type Values [*]_
   * - :class:`MH_AccessType <pcapkit.vendor.mh.access_type.AccessType>`
     - Access Technology Type Option Type Values [*]_
   * - :class:`MH_BindingUpdateFlag <pcapkit.vendor.mh.binding_update_flag.BindingUpdateFlag>`
     - Binding Update Flags [*]_
   * - :class:`MH_BindingACKFlag <pcapkit.vendor.mh.binding_ack_flag.BindingACKFlag>`
     - Binding Acknowledgment Flags [*]_
   * - :class:`MH_DSMIPv6HomeAddress <pcapkit.vendor.mh.dsmipv6_home_address.DSMIPv6HomeAddress>`
     - Dual Stack MIPv6 (DSMIPv6) IPv4 Home Address Option Status Codes [*]_
   * - :class:`MH_BindingRevocation <pcapkit.vendor.mh.binding_revocation.BindingRevocation>`
     - Binding Revocation Type [*]_
   * - :class:`MH_RevocationTrigger <pcapkit.vendor.mh.revocation_trigger.RevocationTrigger>`
     - Revocation Trigger Values [*]_
   * - :class:`MH_RevocationStatusCode <pcapkit.vendor.mh.revocation_status_code.RevocationStatusCode>`
     - Binding Revocation Acknowledgement Status Codes [*]_
   * - :class:`MH_HomeAddressReply <pcapkit.vendor.mh.home_address_reply.HomeAddressReply>`
     - IPv4 Home Address Reply Status Codes [*]_
   * - :class:`MH_DHCPSupportMode <pcapkit.vendor.mh.dhcp_support_mode.DHCPSupportMode>`
     - IPv4 DHCP Support Mode Flags [*]_
   * - :class:`MH_HandoverInitiateFlag <pcapkit.vendor.mh.handover_initiate_flag.HandoverInitiateFlag>`
     - Handover Initiate Flags [*]_
   * - :class:`MH_HandoverACKFlag <pcapkit.vendor.mh.handover_ack_flag.HandoverACKFlag>`
     - Handover Acknowledge Flags [*]_
   * - :class:`MH_HandoverACKStatus <pcapkit.vendor.mh.handover_ack_status.HandoverACKStatus>`
     - Handover Initiate Status Codes [*]_
   * - :class:`MH_HandoverACKStatus <pcapkit.vendor.mh.handover_ack_status.HandoverACKStatus>`
     - Handover Acknowledge Status Codes [*]_

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

"""

from pcapkit.vendor.mh.packet import Packet as MH_Packet
from pcapkit.vendor.mh.option import Option as MH_Option
from pcapkit.vendor.mh.dns_status_code import DNSStatusCode as MH_DNSStatusCode
from pcapkit.vendor.mh.ack_status_code import ACKStatusCode as MH_ACKStatusCode
from pcapkit.vendor.mh.mn_id_subtype import MNIDSubtype as MH_MNIDSubtype
from pcapkit.vendor.mh.status_code import StatusCode as MH_StatusCode
from pcapkit.vendor.mh.enumerating_algorithm import EnumeratingAlgorithm as MH_EnumeratingAlgorithm
from pcapkit.vendor.mh.auth_subtype import AuthSubtype as MH_AuthSubtype
from pcapkit.vendor.mh.handoff_type import HandoffType as MH_HandoffType
from pcapkit.vendor.mh.access_type import AccessType as MH_AccessType
from pcapkit.vendor.mh.binding_update_flag import BindingUpdateFlag as MH_BindingUpdateFlag
from pcapkit.vendor.mh.binding_ack_flag import BindingACKFlag as MH_BindingACKFlag
from pcapkit.vendor.mh.dsmipv6_home_address import DSMIPv6HomeAddress as MH_DSMIPv6HomeAddress
from pcapkit.vendor.mh.binding_revocation import BindingRevocation as MH_BindingRevocation
from pcapkit.vendor.mh.revocation_trigger import RevocationTrigger as MH_RevocationTrigger
from pcapkit.vendor.mh.revocation_status_code import RevocationStatusCode as MH_RevocationStatusCode
from pcapkit.vendor.mh.home_address_reply import HomeAddressReply as MH_HomeAddressReply
from pcapkit.vendor.mh.dhcp_support_mode import DHCPSupportMode as MH_DHCPSupportMode
from pcapkit.vendor.mh.handover_initiate_flag import HandoverInitiateFlag as MH_HandoverInitiateFlag
from pcapkit.vendor.mh.handover_ack_flag import HandoverACKFlag as MH_HandoverACKFlag
from pcapkit.vendor.mh.handover_ack_status import HandoverACKStatus as MH_HandoverACKStatus
from pcapkit.vendor.mh.handover_ack_status import HandoverACKStatus as MH_HandoverACKStatus

__all__ = [
    'MH_Packet', 'MH_Option', 'MH_DNSStatusCode', 'MH_ACKStatusCode',
    'MH_MNIDSubtype', 'MH_StatusCode', 'MH_EnumeratingAlgorithm',
    'MH_AuthSubtype', 'MH_HandoffType', 'MH_AccessType',
    'MH_BindingUpdateFlag', 'MH_BindingACKFlag', 'MH_DSMIPv6HomeAddress',
    'MH_BindingRevocation', 'MH_RevocationTrigger', 'MH_RevocationStatusCode',
    'MH_HomeAddressReply', 'MH_DHCPSupportMode', 'MH_HandoverInitiateFlag',
    'MH_HandoverACKFlag', 'MH_HandoverACKStatus', 'MH_HandoverACKStatus',
]
