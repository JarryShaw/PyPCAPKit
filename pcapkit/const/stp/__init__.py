# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.stp.protocol.STP` Constant Enumerations
====================================================================================

.. module:: pcapkit.const.stp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.stp.protocol.STP` implementations.
Available enumerations include:

.. list-table::

   * - :class:`STP_ProtocolVersion <pcapkit.const.stp.protocol_version.ProtocolVersion>`
     - STP Protocol Version Identifiers
   * - :class:`STP_BPDUType <pcapkit.const.stp.bpdu_type.BPDUType>`
     - STP BPDU Types
   * - :class:`STP_PortRole <pcapkit.const.stp.port_role.PortRole>`
     - STP Port Roles

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.stp.bpdu_type import BPDUType as STP_BPDUType
    from pcapkit.const.stp.port_role import PortRole as STP_PortRole
    from pcapkit.const.stp.protocol_version import ProtocolVersion as STP_ProtocolVersion

__all__ = ['STP_ProtocolVersion', 'STP_BPDUType', 'STP_PortRole']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'STP_ProtocolVersion': ('protocol_version', 'ProtocolVersion'),
    'STP_BPDUType': ('bpdu_type', 'BPDUType'),
    'STP_PortRole': ('port_role', 'PortRole'),
})
