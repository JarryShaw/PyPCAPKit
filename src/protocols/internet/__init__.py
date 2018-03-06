#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Base Class for Internet Layer
from jspcap.protocols.internet.internet import Internet

# Utility Classes for Protocols
from jspcap.protocols.internet.ah import AH
from jspcap.protocols.internet.ipv4 import IPv4
from jspcap.protocols.internet.ipv6 import IPv6
from jspcap.protocols.internet.ipx import IPX

# Ethertype IEEE 802 Numbers
from jspcap.protocols.internet.internet import ETHERTYPE

# Deprecated / Base Classes
from jspcap.protocols.internet.ip import IP
from jspcap.protocols.internet.ipsec import IPsec
