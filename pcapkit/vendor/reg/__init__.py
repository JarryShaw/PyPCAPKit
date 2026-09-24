# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Protocol Type Registry Vendor Crawlers
============================================

.. module:: pcapkit.vendor.reg

This module contains all vendor crawlers of protocol type registry
implementations. Available enumerations include:

.. list-table::

   * - :class:`LINKTYPE <pcapkit.vendor.reg.linktype.LinkType>`
     - Link-Layer Header Type Values [*]_
   * - :class:`ETHERTYPE <pcapkit.vendor.reg.ethertype.EtherType>`
     - Ethertype IEEE 802 Numbers [*]_
   * - :class:`TRANSTYPE <pcapkit.vendor.reg.transtype.TransType>`
     - Transport Layer Protocol Numbers [*]_
   * - :class:`APPTYPE <pcapkit.vendor.reg.apptype.apptype.AppType>`
     - Application Layer Protocol Numbers (Service Name and Transport Protocol Port Number Registry) [*]_

The application layer registry is a package rather than a single crawler: IANA
keys every assignment on a ``(service, port, transport)`` triple, so it is one
crawler per transport protocol -- :class:`TCP <pcapkit.vendor.reg.apptype.tcp.TCP>`,
:class:`UDP <pcapkit.vendor.reg.apptype.udp.UDP>`,
:class:`SCTP <pcapkit.vendor.reg.apptype.sctp.SCTP>` and
:class:`DCCP <pcapkit.vendor.reg.apptype.dccp.DCCP>` -- alongside the base they
all render against. See :mod:`pcapkit.vendor.reg.apptype`.

.. [*] http://www.tcpdump.org/linktypes.html
.. [*] https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1
.. [*] https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
.. [*] https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?

"""

from pcapkit.vendor.reg.apptype import DCCP as AppType_DCCP
from pcapkit.vendor.reg.apptype import SCTP as AppType_SCTP
from pcapkit.vendor.reg.apptype import TCP as AppType_TCP
from pcapkit.vendor.reg.apptype import UDP as AppType_UDP
from pcapkit.vendor.reg.apptype import AppType
from pcapkit.vendor.reg.ethertype import EtherType
from pcapkit.vendor.reg.linktype import LinkType
from pcapkit.vendor.reg.transtype import TransType

__all__ = ['EtherType', 'LinkType', 'TransType', 'AppType',
           'AppType_TCP', 'AppType_UDP', 'AppType_SCTP', 'AppType_DCCP']
