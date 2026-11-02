# -*- coding: utf-8 -*-
"""data models for link layer protocols"""

# Address Resolution Protocol
from pcapkit.protocols.data.link.arp import ARP
from pcapkit.protocols.data.link.arp import Address as ARP_Address
from pcapkit.protocols.data.link.arp import Type as ARP_Type

# Ethernet Protocol
from pcapkit.protocols.data.link.ethernet import Ethernet

# Frame Relay Access Device
from pcapkit.protocols.data.link.frad import FRAD

# Generic Routing Encapsulation
from pcapkit.protocols.data.link.gre import GRE

# IEEE 802.11 MAC Header
from pcapkit.protocols.data.link.ieee802_11 import IEEE802_11
from pcapkit.protocols.data.link.ieee802_11 import FrameControl as IEEE802_11_FrameControl
from pcapkit.protocols.data.link.ieee802_11 import HTControl as IEEE802_11_HTControl
from pcapkit.protocols.data.link.ieee802_11 import QoSControl as IEEE802_11_QoSControl
from pcapkit.protocols.data.link.ieee802_11 import SequenceControl as IEEE802_11_SequenceControl

# Layer Two Tunnelling Protocol
from pcapkit.protocols.data.link.l2tp import L2TP
from pcapkit.protocols.data.link.l2tp import Flags as L2TP_Flags

# Linux "Cooked" Capture Encapsulation
from pcapkit.protocols.data.link.linux_sll1 import LinuxSLL1
from pcapkit.protocols.data.link.linux_sll2 import LinuxSLL2

# BSD Loopback Encapsulation
from pcapkit.protocols.data.link.loopback import Loopback

# Netlink Socket Framing
from pcapkit.protocols.data.link.netlink import Netlink

# IEEE 802.11 Radiotap Header
from pcapkit.protocols.data.link.radiotap import EHT as Radiotap_EHT
from pcapkit.protocols.data.link.radiotap import FHSS as Radiotap_FHSS
from pcapkit.protocols.data.link.radiotap import HE as Radiotap_HE
from pcapkit.protocols.data.link.radiotap import HEMU as Radiotap_HEMU
from pcapkit.protocols.data.link.radiotap import LSIG as Radiotap_LSIG
from pcapkit.protocols.data.link.radiotap import MCS as Radiotap_MCS
from pcapkit.protocols.data.link.radiotap import S1G as Radiotap_S1G
from pcapkit.protocols.data.link.radiotap import TLV as Radiotap_TLV
from pcapkit.protocols.data.link.radiotap import TSFT as Radiotap_TSFT
from pcapkit.protocols.data.link.radiotap import USIG as Radiotap_USIG
from pcapkit.protocols.data.link.radiotap import VHT as Radiotap_VHT
from pcapkit.protocols.data.link.radiotap import AMPDUStatus as Radiotap_AMPDUStatus
from pcapkit.protocols.data.link.radiotap import Antenna as Radiotap_Antenna
from pcapkit.protocols.data.link.radiotap import AntennaNoise as Radiotap_AntennaNoise
from pcapkit.protocols.data.link.radiotap import AntennaSignal as Radiotap_AntennaSignal
from pcapkit.protocols.data.link.radiotap import Channel as Radiotap_Channel
from pcapkit.protocols.data.link.radiotap import DataRetries as Radiotap_DataRetries
from pcapkit.protocols.data.link.radiotap import DBAntennaNoise as Radiotap_DBAntennaNoise
from pcapkit.protocols.data.link.radiotap import DBAntennaSignal as Radiotap_DBAntennaSignal
from pcapkit.protocols.data.link.radiotap import DBmTXPower as Radiotap_DBmTXPower
from pcapkit.protocols.data.link.radiotap import DBTXAttenuation as Radiotap_DBTXAttenuation
from pcapkit.protocols.data.link.radiotap import Flags as Radiotap_Flags
from pcapkit.protocols.data.link.radiotap import HEData1 as Radiotap_HEData1
from pcapkit.protocols.data.link.radiotap import HEData2 as Radiotap_HEData2
from pcapkit.protocols.data.link.radiotap import HEMUFlags1 as Radiotap_HEMUFlags1
from pcapkit.protocols.data.link.radiotap import HEMUFlags2 as Radiotap_HEMUFlags2
from pcapkit.protocols.data.link.radiotap import HEMUOtherUser as Radiotap_HEMUOtherUser
from pcapkit.protocols.data.link.radiotap import LockQuality as Radiotap_LockQuality
from pcapkit.protocols.data.link.radiotap import MCSFlags as Radiotap_MCSFlags
from pcapkit.protocols.data.link.radiotap import Radiotap
from pcapkit.protocols.data.link.radiotap import RadiotapField as Radiotap_Field
from pcapkit.protocols.data.link.radiotap import RadiotapNamespace as Radiotap_RadiotapNamespace
from pcapkit.protocols.data.link.radiotap import Rate as Radiotap_Rate
from pcapkit.protocols.data.link.radiotap import RTSRetries as Radiotap_RTSRetries
from pcapkit.protocols.data.link.radiotap import RXFlags as Radiotap_RXFlags
from pcapkit.protocols.data.link.radiotap import Timestamp as Radiotap_Timestamp
from pcapkit.protocols.data.link.radiotap import TLVFields as Radiotap_TLVFields
from pcapkit.protocols.data.link.radiotap import TXAttenuation as Radiotap_TXAttenuation
from pcapkit.protocols.data.link.radiotap import TXFlags as Radiotap_TXFlags
from pcapkit.protocols.data.link.radiotap import Unknown as Radiotap_Unknown
from pcapkit.protocols.data.link.radiotap import USIGCommon as Radiotap_USIGCommon
from pcapkit.protocols.data.link.radiotap import VendorNamespace as Radiotap_VendorNamespace
from pcapkit.protocols.data.link.radiotap import VendorTLV as Radiotap_VendorTLV
from pcapkit.protocols.data.link.radiotap import ZeroLengthPSDU as Radiotap_ZeroLengthPSDU

# 802.1Q/802.1ad VLAN Tag Types
from pcapkit.protocols.data.link.vlan import TCI as VLAN_TCI
from pcapkit.protocols.data.link.vlan import VLAN

__all__ = [
    # Address Resolution Protocol
    'ARP', 'ARP_Address', 'ARP_Type',

    # Ethernet Protocol
    'Ethernet',

    # Frame Relay Access Device
    'FRAD',

    # Generic Routing Encapsulation
    'GRE',

    # IEEE 802.11 MAC Header
    'IEEE802_11', 'IEEE802_11_FrameControl', 'IEEE802_11_SequenceControl',
    'IEEE802_11_QoSControl', 'IEEE802_11_HTControl',

    # Layer Two Tunnelling Protocol
    'L2TP', 'L2TP_Flags',

    # Linux "Cooked" Capture Encapsulation
    'LinuxSLL1', 'LinuxSLL2',

    # BSD Loopback Encapsulation
    'Loopback',

    # Netlink Socket Framing
    'Netlink',

    # IEEE 802.11 Radiotap Header
    'Radiotap', 'Radiotap_Field', 'Radiotap_Unknown', 'Radiotap_TSFT', 'Radiotap_Flags',
    'Radiotap_Rate', 'Radiotap_Channel', 'Radiotap_FHSS', 'Radiotap_AntennaSignal',
    'Radiotap_AntennaNoise', 'Radiotap_LockQuality', 'Radiotap_TXAttenuation',
    'Radiotap_DBTXAttenuation', 'Radiotap_DBmTXPower', 'Radiotap_Antenna',
    'Radiotap_DBAntennaSignal', 'Radiotap_DBAntennaNoise', 'Radiotap_RXFlags',
    'Radiotap_TXFlags', 'Radiotap_RTSRetries', 'Radiotap_DataRetries', 'Radiotap_MCS',
    'Radiotap_MCSFlags', 'Radiotap_AMPDUStatus', 'Radiotap_VHT',
    'Radiotap_Timestamp', 'Radiotap_HE', 'Radiotap_HEData1', 'Radiotap_HEData2', 'Radiotap_HEMU',
    'Radiotap_HEMUFlags1', 'Radiotap_HEMUFlags2', 'Radiotap_HEMUOtherUser',
    'Radiotap_ZeroLengthPSDU', 'Radiotap_LSIG', 'Radiotap_TLVFields',
    'Radiotap_RadiotapNamespace', 'Radiotap_VendorNamespace', 'Radiotap_S1G', 'Radiotap_USIG',
    'Radiotap_USIGCommon', 'Radiotap_EHT', 'Radiotap_TLV', 'Radiotap_VendorTLV',

    # 802.1Q/802.1ad VLAN Tag Types
    'VLAN', 'VLAN_TCI',
]
