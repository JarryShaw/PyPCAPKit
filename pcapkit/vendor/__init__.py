# -*- coding: utf-8 -*-
# pylint: disable=unused-import, unused-wildcard-import
"""Web crawlers for constant enumerations."""

# base crawler
from pcapkit.vendor.default import Vendor

# IANA registration
from pcapkit.vendor.reg import *

# per protocol
from pcapkit.vendor.arp import *
from pcapkit.vendor.ftp import *
from pcapkit.vendor.hip import *
from pcapkit.vendor.http import *
from pcapkit.vendor.ipv4 import *
from pcapkit.vendor.ipv6 import *
from pcapkit.vendor.ipx import *
from pcapkit.vendor.mh import *
from pcapkit.vendor.ospf import *
from pcapkit.vendor.tcp import *
from pcapkit.vendor.vlan import *

__all__ = [
    # Protocol Registration
    'EtherType', 'LinkType', 'TransType',
    # ARP
    'ARP_Hardware', 'ARP_Operation',
    # FTP
    'FTP_Command', 'FTP_ReturnCode',
    # HIP
    'HIP_Certificate', 'HIP_Cipher', 'HIP_DITypes', 'HIP_ECDSACurve', 'HIP_ECDSALowCurve',
    'HIP_ESPTransformSuite', 'HIP_Group', 'HIP_HIAlgorithm', 'HIP_HITSuite', 'HIP_NATTraversal',
    'HIP_NotifyMessage', 'HIP_Packet', 'HIP_Parameter', 'HIP_Registration', 'HIP_RegistrationFailure',
    'HIP_Suite', 'HIP_Transport',
    # HTTP
    'HTTP_ErrorCode', 'HTTP_Frame', 'HTTP_Setting',
    # IPv4
    'IPv4_ClassificationLevel', 'IPv4_OptionClass', 'IPv4_OptionNumber', 'IPv4_ProtectionAuthority',
    'IPv4_QSFunction', 'IPv4_RouterAlert', 'IPv4_ToSDelay', 'IPv4_ToSECN', 'IPv4_ToSPrecedence',
    'IPv4_ToSReliability', 'IPv4_ToSThroughput',
    # IPv6
    'IPv6_ExtensionHeader', 'IPv6_Option', 'IPv6_QSFunction', 'IPv6_RouterAlert', 'IPv6_Routing',
    'IPv6_SeedID', 'IPv6_TaggerID',
    # IPX
    'IPX_Packet', 'IPX_Socket',
    # MH
    'MH_Packet',
    # OSPF
    'OSPF_Authentication', 'OSPF_Packet',
    # TCP
    'TCP_Checksum', 'TCP_Option', 'TCP_MPTCPOption',
    # VLAN
    'VLAN_PriorityLevel',
]
