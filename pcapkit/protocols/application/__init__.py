# -*- coding: utf-8 -*-
# pylint: disable=unused-import,fixme
"""Application Layer Protocols
=================================

.. module:: pcapkit.protocols.application

:mod:`pcapkit.protocols.application` is collection of all protocols in
application layer, with detailed implementation and methods.

"""
# TODO: Implements BGP, DHCP, DHCPv6, DNS, IMAP, LDAP, MQTT,
#       NNTP, NTP, ONC:RPC, POP, RIP, RTP, SIP, SMTP, SNMP,
#       SSH, TELNET, TLS/SSL, XMPP.

# Base Class for Internet Layer
from pcapkit.protocols.application.application import Application

# Utility Classes for Protocols
from pcapkit.protocols.application.ftp import FTP, FTP_DATA
from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

# Deprecated / Base Classes
from pcapkit.protocols.application.http import HTTP

# Transport Layer Protocol Numbers
from pcapkit.const.reg.apptype import AppType as APPTYPE

__all__ = [
    'APPTYPE',
    'FTP', 'FTP_DATA',
    'HTTP', 'HTTPv1', 'HTTPv2',
]
