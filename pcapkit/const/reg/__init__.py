# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Protocol Type Registry Constant Enumerations
==================================================

.. module:: pcapkit.const.reg

This module contains all constant enumerations of protocol type registry
implementations. Available enumerations include:

.. list-table::

   * - :class:`LINKTYPE <pcapkit.const.reg.linktype.LinkType>`
     - Link-Layer Header Type Values [*]_
   * - :class:`ETHERTYPE <pcapkit.const.reg.ethertype.EtherType>`
     - Ethertype IEEE 802 Numbers [*]_
   * - :class:`TRANSTYPE <pcapkit.const.reg.transtype.TransType>`
     - Transport Layer Protocol Numbers [*]_
   * - :class:`APPTYPE <pcapkit.const.reg.apptype.apptype.AppType>`
     - Application Layer Protocol Numbers (Service Name and Transport Protocol Port Number Registry) [*]_

The application layer registry is a package rather than a single enumeration:
IANA keys every assignment on a ``(service, port, transport)`` triple, so it is
one enumeration per transport protocol -- :class:`TCP <pcapkit.const.reg.apptype.tcp.TCP>`,
:class:`UDP <pcapkit.const.reg.apptype.udp.UDP>`,
:class:`SCTP <pcapkit.const.reg.apptype.sctp.SCTP>` and
:class:`DCCP <pcapkit.const.reg.apptype.dccp.DCCP>` -- sharing the memberless
base ``APPTYPE`` they all subclass. See :mod:`pcapkit.const.reg.apptype`.

.. [*] http://www.tcpdump.org/linktypes.html
.. [*] https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1
.. [*] https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
.. [*] https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?

"""

from pcapkit.const.reg.apptype import AppType as APPTYPE
from pcapkit.const.reg.ethertype import EtherType as ETHERTYPE
from pcapkit.const.reg.linktype import LinkType as LINKTYPE
from pcapkit.const.reg.transtype import TransType as TRANSTYPE

__all__ = ['ETHERTYPE', 'LINKTYPE', 'TRANSTYPE', 'APPTYPE']
