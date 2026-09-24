# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Application Layer Protocol Numbers Vendor Crawlers
=======================================================

.. module:: pcapkit.vendor.reg.apptype

This module contains the vendor crawlers for the **Application Layer Protocol
Numbers** registry. IANA keys every assignment on a ``(service, port,
transport)`` triple, so the registry is one crawler per transport protocol plus
the transport-agnostic base they all render against. Available crawlers include:

.. list-table::

   * - :class:`AppType <pcapkit.vendor.reg.apptype.apptype.AppType>`
     - Application Layer Protocol Numbers (base registry) [*]_
   * - :class:`TCP <pcapkit.vendor.reg.apptype.tcp.TCP>`
     - Application Layer Protocol Numbers (TCP)
   * - :class:`UDP <pcapkit.vendor.reg.apptype.udp.UDP>`
     - Application Layer Protocol Numbers (UDP)
   * - :class:`SCTP <pcapkit.vendor.reg.apptype.sctp.SCTP>`
     - Application Layer Protocol Numbers (SCTP)
   * - :class:`DCCP <pcapkit.vendor.reg.apptype.dccp.DCCP>`
     - Application Layer Protocol Numbers (DCCP)

.. [*] https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?

"""

from pcapkit.vendor.reg.apptype.apptype import AppType
from pcapkit.vendor.reg.apptype.dccp import DCCP
from pcapkit.vendor.reg.apptype.sctp import SCTP
from pcapkit.vendor.reg.apptype.tcp import TCP
from pcapkit.vendor.reg.apptype.udp import UDP

__all__ = ['AppType', 'TCP', 'UDP', 'SCTP', 'DCCP']
