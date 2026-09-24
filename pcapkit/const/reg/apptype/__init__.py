# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Application Layer Protocol Numbers Constant Enumerations
============================================================

.. module:: pcapkit.const.reg.apptype

This module contains the constant enumerations for the **Application Layer
Protocol Numbers** registry. IANA keys every assignment on a ``(service, port,
transport)`` triple, so the registry is one enumeration per transport protocol,
sharing the transport-agnostic base they all subclass. Available enumerations
include:

.. list-table::

   * - :class:`AppType <pcapkit.const.reg.apptype.apptype.AppType>`
     - Application Layer Protocol Numbers (base registry, no members) [*]_
   * - :class:`TCP <pcapkit.const.reg.apptype.tcp.TCP>`
     - Application Layer Protocol Numbers (TCP)
   * - :class:`UDP <pcapkit.const.reg.apptype.udp.UDP>`
     - Application Layer Protocol Numbers (UDP)
   * - :class:`SCTP <pcapkit.const.reg.apptype.sctp.SCTP>`
     - Application Layer Protocol Numbers (SCTP)
   * - :class:`DCCP <pcapkit.const.reg.apptype.dccp.DCCP>`
     - Application Layer Protocol Numbers (DCCP)

.. [*] https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?

:class:`~pcapkit.const.reg.apptype.apptype.AppType` holds no members. It is the
type every member is an instance of, so ``isinstance(TCP.http, AppType)`` holds
and a caller that only has a port and a transport protocol can still reach the
right registry through :meth:`AppType.get
<pcapkit.const.reg.apptype.apptype.AppType.get>`.

"""

from pcapkit.const.reg.apptype.apptype import AppType, TransportProtocol
from pcapkit.const.reg.apptype.dccp import DCCP
from pcapkit.const.reg.apptype.sctp import SCTP
from pcapkit.const.reg.apptype.tcp import TCP
from pcapkit.const.reg.apptype.udp import UDP

__all__ = ['AppType', 'TransportProtocol', 'TCP', 'UDP', 'SCTP', 'DCCP']

# NOTE: this is what makes ``AppType.get(port, proto=...)`` work on the base
# class, which is where every caller in the library addresses it. It cannot live
# in ``apptype.py``: that module is imported *by* all four registries, so it
# cannot import them back. Here is the first point at which all four exist.
AppType.__registries__[TransportProtocol.tcp] = TCP
AppType.__registries__[TransportProtocol.udp] = UDP
AppType.__registries__[TransportProtocol.sctp] = SCTP
AppType.__registries__[TransportProtocol.dccp] = DCCP
