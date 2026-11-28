# -*- coding: utf-8 -*-
# pylint: disable=unused-import,fixme
"""Application Layer Protocols
=================================

.. module:: pcapkit.protocols.application

:mod:`pcapkit.protocols.application` holds the application layer protocols.

.. versionchanged:: 1.6.0

   Each protocol class, and the base class
   :class:`~pcapkit.protocols.application.application.Application`, is imported on
   first access through :func:`~pcapkit.utilities.importlib.lazy_exports`, not with
   this package (:issue:`2730`).

"""
# TODO: Implements BGP, DHCPv6, IMAP, LDAP, MQTT,
#       NNTP, NTP, ONC:RPC, POP, RIP, RTP, SIP, SMTP, SNMP,
#       SSH, TELNET, XMPP.
#
# NB: NGAP's decoder, ``pycrate``, is an optional dependency imported only
#     when parsing; see pcapkit.protocols.application.ngap.protocol.

from typing import TYPE_CHECKING

# Application Layer Protocol Numbers
from pcapkit.const.reg.apptype import AppType as APPTYPE
from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    # Base Class for Application Layer
    from pcapkit.protocols.application.application import Application

    # Application Layer Protocols
    from pcapkit.protocols.application.bootp import BOOTP
    from pcapkit.protocols.application.dhcpv4 import DHCPv4
    from pcapkit.protocols.application.dns import DNS
    from pcapkit.protocols.application.ftp import FTP
    from pcapkit.protocols.application.ftp_data import FTP_DATA
    from pcapkit.protocols.application.httpv1 import HTTPv1
    from pcapkit.protocols.application.httpv2 import HTTPv2
    from pcapkit.protocols.application.ngap import NGAP
    from pcapkit.protocols.application.ospfv1 import OSPFv1
    from pcapkit.protocols.application.ospfv2 import OSPFv2
    from pcapkit.protocols.application.ospfv3 import OSPFv3
    from pcapkit.protocols.application.rarp import RARP
    from pcapkit.protocols.application.drarp import DRARP
    from pcapkit.protocols.application.sslv2 import SSLv2
    from pcapkit.protocols.application.tls import TLS
    from pcapkit.protocols.application.sslv3 import SSLv3
    from pcapkit.protocols.application.dtls import DTLS
    from pcapkit.protocols.application.stpv0 import STPv0
    from pcapkit.protocols.application.rstp import RSTP
    from pcapkit.protocols.application.mstp import MSTP

    # Base Classes
    from pcapkit.protocols.application.dhcp import DHCP
    from pcapkit.protocols.application.http import HTTP
    from pcapkit.protocols.application.ospf import OSPF
    from pcapkit.protocols.application.ssl import SSL
    from pcapkit.protocols.application.stp import STP

__all__ = [
    'APPTYPE',
    'DHCP', 'BOOTP', 'DHCPv4',
    'DNS',
    'FTP', 'FTP_DATA',
    'HTTP', 'HTTPv1', 'HTTPv2',
    'NGAP',
    'OSPF', 'OSPFv1', 'OSPFv2', 'OSPFv3',
    'RARP', 'DRARP',
    'SSL', 'SSLv2', 'SSLv3', 'TLS', 'DTLS',
    'STP', 'STPv0', 'RSTP', 'MSTP',
]

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'Application': ('application', 'Application'),
    'DHCP': ('dhcp', 'DHCP'),
    'BOOTP': ('bootp', 'BOOTP'),
    'DHCPv4': ('dhcpv4', 'DHCPv4'),
    'DNS': ('dns', 'DNS'),
    'FTP': ('ftp', 'FTP'),
    'FTP_DATA': ('ftp_data', 'FTP_DATA'),
    'HTTP': ('http', 'HTTP'),
    'HTTPv1': ('httpv1', 'HTTPv1'),
    'HTTPv2': ('httpv2', 'HTTPv2'),
    'NGAP': ('ngap', 'NGAP'),
    'OSPF': ('ospf', 'OSPF'),
    'OSPFv1': ('ospfv1', 'OSPFv1'),
    'OSPFv2': ('ospfv2', 'OSPFv2'),
    'OSPFv3': ('ospfv3', 'OSPFv3'),
    'RARP': ('rarp', 'RARP'),
    'DRARP': ('drarp', 'DRARP'),
    'SSL': ('ssl', 'SSL'),
    'SSLv2': ('sslv2', 'SSLv2'),
    'SSLv3': ('sslv3', 'SSLv3'),
    'TLS': ('tls', 'TLS'),
    'DTLS': ('dtls', 'DTLS'),
    'STP': ('stp', 'STP'),
    'STPv0': ('stpv0', 'STPv0'),
    'RSTP': ('rstp', 'RSTP'),
    'MSTP': ('mstp', 'MSTP'),
})
