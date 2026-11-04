# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.vlan.protocol.VLAN` Constant Enumerations
===============================================================================

.. module:: pcapkit.const.vlan

This module contains all constant enumerations of
:class:`~pcapkit.protocols.link.vlan.protocol.VLAN` implementations. Available
enumerations include:

.. list-table::

   * - :class:`VLAN_PriorityLevel <pcapkit.const.vlan.priority_level.PriorityLevel>`
     - Priority Levels [*]_

.. [*] https://en.wikipedia.org/wiki/IEEE_P802.1p#Priority_levels

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.vlan.priority_level import PriorityLevel as VLAN_PriorityLevel

__all__ = ['VLAN_PriorityLevel']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'VLAN_PriorityLevel': ('priority_level', 'PriorityLevel'),
})
