# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.dhcp.protocol.DHCP` Constant Enumerations
======================================================================================

.. module:: pcapkit.const.dhcp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.dhcp.protocol.DHCP` implementations,
i.e. :class:`~pcapkit.protocols.application.bootp.protocol.BOOTP` and
:class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4`. Available
enumerations include:

.. list-table::

   * - :class:`DHCP_Opcode <pcapkit.const.dhcp.opcode.Opcode>`
     - BOOTP Message Op Codes
   * - :class:`DHCP_Option <pcapkit.const.dhcp.option.Option>`
     - BOOTP Vendor Extensions and DHCP Options
   * - :class:`DHCP_MessageType <pcapkit.const.dhcp.message_type.MessageType>`
     - DHCP Message Type 53 Values
   * - :class:`DHCP_RelayAgentSubOption <pcapkit.const.dhcp.relay_agent_suboption.RelayAgentSubOption>`
     - DHCP Relay Agent Sub-Option Codes

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.dhcp.message_type import MessageType as DHCP_MessageType
    from pcapkit.const.dhcp.opcode import Opcode as DHCP_Opcode
    from pcapkit.const.dhcp.option import Option as DHCP_Option
    from pcapkit.const.dhcp.relay_agent_suboption import \
        RelayAgentSubOption as DHCP_RelayAgentSubOption

__all__ = ['DHCP_Opcode', 'DHCP_Option', 'DHCP_MessageType', 'DHCP_RelayAgentSubOption']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'DHCP_Opcode': ('opcode', 'Opcode'),
    'DHCP_Option': ('option', 'Option'),
    'DHCP_MessageType': ('message_type', 'MessageType'),
    'DHCP_RelayAgentSubOption': ('relay_agent_suboption', 'RelayAgentSubOption'),
})
