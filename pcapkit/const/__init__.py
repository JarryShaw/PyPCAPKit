# -*- coding: utf-8 -*-
# pylint: disable=unused-import, unused-wildcard-import
"""Constant Enumerations
===========================

This module contains all constant enumerations of :mod:`pcapkit`, which are
automatically generated from the :mod:`pcapkit.vendor` module.

Each enumeration is imported the first time it is reached -- as an attribute
of this package or of the subpackage holding it -- rather than with the
package, through :func:`~pcapkit.utilities.lazy.lazy_exports`
(:issue:`2729`). The subpackages themselves are imported with it, and import
none of their enumerations.

"""
from typing import TYPE_CHECKING

from pcapkit.utilities.lazy import lazy_exports

if TYPE_CHECKING:
    # IANA registration
    from pcapkit.const.reg import *

    # Miscellaneous
    from pcapkit.const.pcapng import *

    # per protocol
    from pcapkit.const.arp import *
    from pcapkit.const.dccp import *
    from pcapkit.const.esp import *
    from pcapkit.const.ftp import *
    from pcapkit.const.hip import *
    from pcapkit.const.http import *
    from pcapkit.const.icmp import *
    from pcapkit.const.icmpv6 import *
    from pcapkit.const.ieee802_11 import *
    from pcapkit.const.igmp import *
    from pcapkit.const.ipv4 import *
    from pcapkit.const.ipv6 import *
    from pcapkit.const.ipx import *
    from pcapkit.const.l2tp import *
    from pcapkit.const.linux import *
    from pcapkit.const.mh import *
    from pcapkit.const.ngap import *
    from pcapkit.const.ospf import *
    from pcapkit.const.radiotap import *
    from pcapkit.const.sctp import *
    from pcapkit.const.sslv2 import *
    from pcapkit.const.tcp import *
    from pcapkit.const.tls import *
    from pcapkit.const.vlan import *

__all__ = [
    # Protocol Registration
    'ETHERTYPE', 'LINKTYPE', 'TRANSTYPE', 'APPTYPE',
    # ARP
    'ARP_Hardware', 'ARP_Operation',
    # DCCP
    'DCCP_PacketType', 'DCCP_ResetCode', 'DCCP_Option', 'DCCP_Feature',
    'DCCP_AckVectorState', 'DCCP_DropCode',
    # ESP
    'ESP_Cipher', 'ESP_Integrity',
    # FTP
    'FTP_Command', 'FTP_ReturnCode',
    # HIP
    'HIP_Certificate', 'HIP_Cipher', 'HIP_DITypes', 'HIP_ECDSACurve', 'HIP_ECDSALowCurve',
    'HIP_ESPTransformSuite', 'HIP_Group', 'HIP_HIAlgorithm', 'HIP_HITSuite', 'HIP_NATTraversal',
    'HIP_NotifyMessage', 'HIP_Packet', 'HIP_Parameter', 'HIP_Registration', 'HIP_RegistrationFailure',
    'HIP_Suite', 'HIP_Transport', 'HIP_EdDSACurve',
    # HTTP
    'HTTP_ErrorCode', 'HTTP_Frame', 'HTTP_Method', 'HTTP_Setting', 'HTTP_Status',
    # ICMP
    'ICMP_Type', 'ICMP_DestinationUnreachableCode', 'ICMP_TimeExceededCode', 'ICMP_ParameterProblemCode',
    # ICMPv6
    'ICMPv6_Type', 'ICMPv6_DestinationUnreachableCode', 'ICMPv6_TimeExceededCode',
    'ICMPv6_ParameterProblemCode',
    # IEEE 802.11
    'IEEE802_11_Type', 'IEEE802_11_ManagementSubtype', 'IEEE802_11_ControlSubtype',
    'IEEE802_11_DataSubtype', 'IEEE802_11_ExtensionSubtype',
    # IGMP
    'IGMP_Type', 'IGMP_RecordType',
    # IPv4
    'IPv4_ClassificationLevel', 'IPv4_OptionClass', 'IPv4_OptionNumber', 'IPv4_ProtectionAuthority',
    'IPv4_QSFunction', 'IPv4_RouterAlert', 'IPv4_ToSDelay', 'IPv4_ToSECN', 'IPv4_ToSPrecedence',
    'IPv4_ToSReliability', 'IPv4_ToSThroughput', 'IPv4_TSFlag',
    # IPv6
    'IPv6_ExtensionHeader', 'IPv6_Option', 'IPv6_QSFunction', 'IPv6_RouterAlert', 'IPv6_Routing',
    'IPv6_SeedID', 'IPv6_SMFDPDMode', 'IPv6_TaggerID', 'IPv6_OptionAction',
    # IPX
    'IPX_Packet', 'IPX_Socket',
    # L2TP
    'L2TP_Type',
    # Linux
    'Linux_ARPHRD',
    # MH
    'MH_Packet', 'MH_Option', 'MH_DNSStatusCode', 'MH_ACKStatusCode',
    'MH_MNIDSubtype', 'MH_StatusCode', 'MH_EnumeratingAlgorithm',
    'MH_AuthSubtype', 'MH_HandoffType', 'MH_AccessType',
    'MH_BindingUpdateFlag', 'MH_BindingACKFlag', 'MH_DSMIPv6HomeAddress',
    'MH_BindingRevocation', 'MH_RevocationTrigger', 'MH_RevocationStatusCode',
    'MH_HomeAddressReply', 'MH_DHCPSupportMode', 'MH_HandoverInitiateFlag',
    'MH_HandoverACKFlag', 'MH_HandoverInitiateStatus', 'MH_HandoverACKStatus',
    'MH_FlowIDStatus', 'MH_FlowIDSuboption', 'MH_TrafficSelector',
    'MH_MNGroupID', 'MH_DSMIP6TLSPacket', 'MH_ANISuboption', 'MH_OperatorID',
    'MH_UpdateNotificationReason', 'MH_UpdateNotificationACKStatus',
    'MH_FlowBindingType', 'MH_FlowBindingIndicationTrigger',
    'MH_FlowBindingACKStatus', 'MH_FlowBindingAction', 'MH_QoSAttribute',
    'MH_LMAControlledMAGSuboption', 'MH_LLACode', 'MH_CGAType',
    'MH_CGAExtension', 'MH_CGASec', 'MH_BindingError',
    # NGAP
    'NGAP_ProcedureCode', 'NGAP_ProtocolIE',
    # OSPF
    'OSPF_Authentication', 'OSPF_Packet',
    # Radiotap
    'Radiotap_FieldType', 'Radiotap_Flags', 'Radiotap_ChannelFlags', 'Radiotap_RXFlags',
    'Radiotap_TXFlags', 'Radiotap_MCSKnown', 'Radiotap_AMPDUFlags', 'Radiotap_VHTKnown',
    'Radiotap_VHTFlags', 'Radiotap_VHTCoding', 'Radiotap_TimestampFlags', 'Radiotap_HEData1Known',
    'Radiotap_HEData2Known', 'Radiotap_HEMUFlags1Known', 'Radiotap_HEMUFlags2Known',
    'Radiotap_HEMUOtherUserKnown', 'Radiotap_LSIGData1', 'Radiotap_S1GKnown',
    'Radiotap_USIGCommonKnown', 'Radiotap_EHTKnown',
    # SCTP
    'SCTP_Chunk', 'SCTP_Parameter', 'SCTP_CauseCode', 'SCTP_PayloadProtocolIdentifier',
    # SSLv2
    'SSLv2_HandshakeType', 'SSLv2_Version',
    # TCP
    'TCP_Checksum', 'TCP_Option', 'TCP_MPTCPOption', 'TCP_Flags',
    # TLS/DTLS
    'TLS_ContentType', 'TLS_HandshakeType', 'TLS_ExtensionType',
    # VLAN
    'VLAN_PriorityLevel',
    # PCAPNG
    'PCAPNG_BlockType', 'PCAPNG_OptionType', 'PCAPNG_HashAlgorithm',
    'PCAPNG_VerdictType', 'PCAPNG_RecordType', 'PCAPNG_SecretsType',
    'PCAPNG_FilterType', 'PCAPNG_TLSKeyLabel',
]

# NOTE: the subpackages whose ``__all__`` this package re-exports, which the
# type checkers star-import above.
__getattr__, __dir__ = lazy_exports(__name__, globals(), packages=(
    'reg', 'pcapng', 'arp', 'dccp', 'esp', 'ftp', 'hip', 'http', 'icmp', 'icmpv6',
    'ieee802_11', 'igmp', 'ipv4', 'ipv6', 'ipx', 'l2tp', 'linux', 'mh', 'ngap', 'ospf',
    'radiotap', 'sctp', 'sslv2', 'tcp', 'tls', 'vlan',
))
