# -*- coding: utf-8 -*-
# pylint: disable=unused-import,fixme
"""Application Layer Protocols
=================================

.. module:: pcapkit.protocols.application

:mod:`pcapkit.protocols.application` is a collection of all protocols in
application layer.

"""
# TODO: Implements BGP, DHCP, DHCPv6, DNS, IMAP, LDAP, MQTT,
#       NNTP, NTP, ONC:RPC, POP, RIP, RTP, SIP, SMTP, SNMP,
#       SSH, TELNET, XMPP.
#
# NB: NGAP's decoder below is an optional
#     dependency; see pcapkit.protocols.application.ngap. Importing the module
#     is free -- ``pycrate`` is imported inside the parse path, not here.

# Base Class for Application Layer
from pcapkit.protocols.application.application import Application

# Utility Classes for Protocols
from pcapkit.protocols.application.ftp import FTP
from pcapkit.protocols.application.ftp_data import FTP_DATA
from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
from pcapkit.protocols.application.ngap import NGAP
from pcapkit.protocols.application.ospf import OSPF
from pcapkit.protocols.application.rarp import RARP
from pcapkit.protocols.application.drarp import DRARP
from pcapkit.protocols.application.sslv2 import SSLv2
from pcapkit.protocols.application.tls import TLS, SSLv3
from pcapkit.protocols.application.dtls import DTLS

# Base Classes
from pcapkit.protocols.application.http import HTTP
from pcapkit.protocols.application.ssl import SSL

# Application Layer Protocol Numbers
from pcapkit.const.reg.apptype import AppType as APPTYPE

__all__ = [
    'APPTYPE',
    'FTP', 'FTP_DATA',
    'HTTP', 'HTTPv1', 'HTTPv2',
    'NGAP',
    'OSPF',
    'RARP', 'DRARP',
    'SSL', 'SSLv2', 'SSLv3', 'TLS', 'DTLS',
]
