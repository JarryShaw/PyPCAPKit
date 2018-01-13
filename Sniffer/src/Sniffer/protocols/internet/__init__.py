#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Base Class for Internet Layer
from .internet import Internet

# Utility Classes for Protocols
from .ah import AH
from .ipv4 import IPv4
from .ipv6 import IPv6
from .ipx import IPX

# Ethertype IEEE 802 Numbers
from .internet import ETHERTYPE

# Deprecated / Base Classes
from .ip import IP
from .ipsec import IPsec
