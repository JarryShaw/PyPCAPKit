# -*- coding: utf-8 -*-
# pylint: disable=unused-import, unused-wildcard-import
"""Vendor Crawlers
=====================

.. module:: pcapkit.vendor

This module contains all web crawlers of :mod:`pcapkit`, which are
automatically generating the :mod:`pcapkit.const` module's constant.
enumerations.

"""

from pcapkit.utilities.compat import ModuleNotFoundError  # pylint: disable=redefined-builtin
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.warnings import VendorWarning, warn

try:
    import requests
    import socks
except ModuleNotFoundError:
    warn("dependency package 'requests[socks]' not found",
         VendorWarning, stacklevel=stacklevel())

try:
    import bs4
    import html5lib
except ModuleNotFoundError:
    warn("dependency package 'beautifulsoup4[html5lib]' not found",
         VendorWarning, stacklevel=stacklevel())

# base crawler
from pcapkit.vendor.default import Vendor

# IANA registration
from pcapkit.vendor.reg import *

# Miscellanous
from pcapkit.vendor.pcapng import *

# per protocol
from pcapkit.vendor.arp import *
from pcapkit.vendor.ftp import *
from pcapkit.vendor.hip import *
from pcapkit.vendor.http import *
from pcapkit.vendor.ipv4 import *
from pcapkit.vendor.ipv6 import *
from pcapkit.vendor.ipx import *
from pcapkit.vendor.l2tp import *
from pcapkit.vendor.mh import *
from pcapkit.vendor.ospf import *
from pcapkit.vendor.tcp import *
from pcapkit.vendor.vlan import *

__all__ = [
    # Protocol Registration
    'EtherType', 'LinkType', 'TransType', 'AppType',
    # ARP
    'ARP_Hardware', 'ARP_Operation',
    # FTP
    'FTP_Command', 'FTP_ReturnCode',
    # HIP
    'HIP_Certificate', 'HIP_Cipher', 'HIP_DITypes', 'HIP_ECDSACurve', 'HIP_ECDSALowCurve',
    'HIP_ESPTransformSuite', 'HIP_Group', 'HIP_HIAlgorithm', 'HIP_HITSuite', 'HIP_NATTraversal',
    'HIP_NotifyMessage', 'HIP_Packet', 'HIP_Parameter', 'HIP_Registration', 'HIP_RegistrationFailure',
    'HIP_Suite', 'HIP_Transport', 'HIP_EdDSACurve',
    # HTTP
    'HTTP_ErrorCode', 'HTTP_Frame', 'HTTP_Method', 'HTTP_Setting', 'HTTP_StatusCode',
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
    # MH
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
    # OSPF
    'OSPF_Authentication', 'OSPF_Packet',
    # TCP
    'TCP_Checksum', 'TCP_Option', 'TCP_MPTCPOption', 'TCP_Flags',
    # VLAN
    'VLAN_PriorityLevel',
    # PCAPNG
    'PCAPNG_BlockType', 'PCAPNG_OptionType', 'PCAPNG_HashAlgorithm',
    'PCAPNG_VerdictType', 'PCAPNG_RecordType', 'PCAPNG_SecretsType',
    'PCAPNG_FilterType',
]
