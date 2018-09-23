# -*- coding: utf-8 -*-
"""application layer protocols

`pcapkit.protocols.application` is collection of all
protocols in application layer, with detailed
implementation and methods.

"""
# Base Class for Internet Layer
from pcapkit.protocols.application.application import Application

# Utility Classes for Protocols
from pcapkit.protocols.application.httpv1 import HTTPv1
from pcapkit.protocols.application.httpv2 import HTTPv2

# Deprecated / Base Classes
from pcapkit.protocols.application.http import HTTP

# TODO: Implements BGP, DHCP, DNS, FTP, IMAP, IDAP, MQTT, NNTP, NTP,
# #     ONC:RPC, POP, RIP, RTP, SIP, SMTP, SNMP, SSH, SSL, TELNET, TLS, XMPP.
__all__ = ['HTTPv1', 'HTTPv2']
