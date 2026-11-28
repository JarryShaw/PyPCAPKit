# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.dhcp.protocol.DHCP` Vendor Crawlers
================================================================================

.. module:: pcapkit.vendor.dhcp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.application.dhcp.protocol.DHCP` implementations,
i.e. :class:`~pcapkit.protocols.application.bootp.protocol.BOOTP` and
:class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4`. Available
enumerations include:

.. list-table::

   * - :class:`DHCP_Opcode <pcapkit.vendor.dhcp.opcode.Opcode>`
     - BOOTP Message Op Codes
   * - :class:`DHCP_Option <pcapkit.vendor.dhcp.option.Option>`
     - BOOTP Vendor Extensions and DHCP Options [*]_
   * - :class:`DHCP_MessageType <pcapkit.vendor.dhcp.message_type.MessageType>`
     - DHCP Message Type 53 Values [*]_
   * - :class:`DHCP_RelayAgentSubOption <pcapkit.vendor.dhcp.relay_agent_suboption.RelayAgentSubOption>`
     - DHCP Relay Agent Sub-Option Codes [*]_

:class:`~pcapkit.vendor.dhcp.opcode.Opcode` reads a ``DATA`` literal, as
:mod:`pcapkit.vendor.linux.arphrd` does (:ref:`const-vendor-pairing`), since
IANA publishes no registry for the two codes of :rfc:`951#section-3`.

.. [*] https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#options
.. [*] https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#message-type-53
.. [*] https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#relay-agent-sub-options

"""

from pcapkit.vendor.dhcp.message_type import MessageType as DHCP_MessageType
from pcapkit.vendor.dhcp.opcode import Opcode as DHCP_Opcode
from pcapkit.vendor.dhcp.option import Option as DHCP_Option
from pcapkit.vendor.dhcp.relay_agent_suboption import \
    RelayAgentSubOption as DHCP_RelayAgentSubOption

__all__ = ['DHCP_Opcode', 'DHCP_Option', 'DHCP_MessageType', 'DHCP_RelayAgentSubOption']
