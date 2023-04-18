# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.vlan.VLAN` Vendor Crawlers
================================================================

.. module:: pcapkit.vendor.vlan

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.link.vlan.VLAN` implementations. Available
enumerations include:

.. list-table::

   * - :const:`VLAN_PriorityLevel <pcapkit.const.vlan.priority_level.PriorityLevel>`
     - Priority Levels [*]_

.. [*] https://en.wikipedia.org/wiki/IEEE_P802.1p#Priority_levels

"""

from pcapkit.vendor.vlan.priority_level import PriorityLevel as VLAN_PriorityLevel

__all__ = ['VLAN_PriorityLevel']
