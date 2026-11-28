# -*- coding: utf-8 -*-
"""The registries of :mod:`pcapkit.const.dhcp`, for :mod:`tests.const.census`."""

#: Each registry, as ``module:QualName``, and its kind.
REGISTRIES = {
    'pcapkit.const.dhcp.message_type:MessageType': 'int',
    'pcapkit.const.dhcp.opcode:Opcode': 'int',
    'pcapkit.const.dhcp.option:Option': 'int',
    'pcapkit.const.dhcp.relay_agent_suboption:RelayAgentSubOption': 'int',
}
