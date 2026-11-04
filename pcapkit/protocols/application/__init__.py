# -*- coding: utf-8 -*-
# pylint: disable=unused-import,fixme
"""Application Layer Protocols
=================================

.. module:: pcapkit.protocols.application

:mod:`pcapkit.protocols.application` is a collection of all protocols in
application layer.

Each protocol class, and the base class
:class:`~pcapkit.protocols.application.application.Application`, is imported the
first time it is reached rather than with this package, through
:func:`~pcapkit.utilities.importlib.lazy_exports` (:issue:`2730`).

"""
# TODO: Implements BGP, DHCP, DHCPv6, DNS, IMAP, LDAP, MQTT,
#       NNTP, NTP, ONC:RPC, POP, RIP, RTP, SIP, SMTP, SNMP,
#       SSH, TELNET, XMPP.
#
# NB: NGAP's decoder below is an optional
#     dependency; see pcapkit.protocols.application.ngap.protocol. Importing the module
#     is free -- ``pycrate`` is imported inside the parse path, not here.

from typing import TYPE_CHECKING

# Application Layer Protocol Numbers
from pcapkit.const.reg.apptype import AppType as APPTYPE
from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    # Base Class for Application Layer
    from pcapkit.protocols.application.application import Application

    # Utility Classes for Protocols
    from pcapkit.protocols.application.ftp import FTP
    from pcapkit.protocols.application.ftp_data import FTP_DATA
    from pcapkit.protocols.application.httpv1 import HTTPv1
    from pcapkit.protocols.application.httpv2 import HTTPv2
    from pcapkit.protocols.application.ngap import NGAP
    from pcapkit.protocols.application.ospf import OSPF
    from pcapkit.protocols.application.rarp import RARP
    from pcapkit.protocols.application.drarp import DRARP
    from pcapkit.protocols.application.sslv2 import SSLv2
    from pcapkit.protocols.application.tls import TLS
    from pcapkit.protocols.application.sslv3 import SSLv3
    from pcapkit.protocols.application.dtls import DTLS

    # Base Classes
    from pcapkit.protocols.application.http import HTTP
    from pcapkit.protocols.application.ssl import SSL

__all__ = [
    'APPTYPE',
    'FTP', 'FTP_DATA',
    'HTTP', 'HTTPv1', 'HTTPv2',
    'NGAP',
    'OSPF',
    'RARP', 'DRARP',
    'SSL', 'SSLv2', 'SSLv3', 'TLS', 'DTLS',
]

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'Application': ('application', 'Application'),
    'FTP': ('ftp', 'FTP'),
    'FTP_DATA': ('ftp_data', 'FTP_DATA'),
    'HTTP': ('http', 'HTTP'),
    'HTTPv1': ('httpv1', 'HTTPv1'),
    'HTTPv2': ('httpv2', 'HTTPv2'),
    'NGAP': ('ngap', 'NGAP'),
    'OSPF': ('ospf', 'OSPF'),
    'RARP': ('rarp', 'RARP'),
    'DRARP': ('drarp', 'DRARP'),
    'SSL': ('ssl', 'SSL'),
    'SSLv2': ('sslv2', 'SSLv2'),
    'SSLv3': ('sslv3', 'SSLv3'),
    'TLS': ('tls', 'TLS'),
    'DTLS': ('dtls', 'DTLS'),
})
