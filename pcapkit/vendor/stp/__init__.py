# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.stp.protocol.STP` Vendor Crawlers
==============================================================================

.. module:: pcapkit.vendor.stp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.application.stp.protocol.STP` implementations.
Available vendor crawlers include:

.. list-table::

   * - :class:`STP_ProtocolVersion <pcapkit.vendor.stp.protocol_version.ProtocolVersion>`
     - STP Protocol Version Identifiers
   * - :class:`STP_BPDUType <pcapkit.vendor.stp.bpdu_type.BPDUType>`
     - STP BPDU Types
   * - :class:`STP_PortRole <pcapkit.vendor.stp.port_role.PortRole>`
     - STP Port Roles

None of these crawlers crawls, so each reads a ``DATA`` literal instead of
fetching a URL, the shape :mod:`pcapkit.vendor.linux.arphrd` takes
(:ref:`const-vendor-pairing`). The values are fixed by the text of
:ieee:`802.1D-2004` clause 9 and :ieee:`802.1Q-2022` clause 14, which no
registry publishes and which are paywalled. They are transcribed from Wireshark's
``packet-bpdu.c``, and agree with tcpdump's ``print-stp.c`` and with mstpd's
``mstp.h``, whose ``port_encoded_role_t`` gives the Master Port its ``0``.

"""

from pcapkit.vendor.stp.bpdu_type import BPDUType as STP_BPDUType
from pcapkit.vendor.stp.port_role import PortRole as STP_PortRole
from pcapkit.vendor.stp.protocol_version import ProtocolVersion as STP_ProtocolVersion

__all__ = ['STP_ProtocolVersion', 'STP_BPDUType', 'STP_PortRole']
