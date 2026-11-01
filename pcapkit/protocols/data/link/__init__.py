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
from pcapkit.protocols.data.link.radiotap import Radiotap

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
    'Radiotap',

    # 802.1Q/802.1ad VLAN Tag Types
    'VLAN', 'VLAN_TCI',
]
