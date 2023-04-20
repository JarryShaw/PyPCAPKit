================================================================
:class:`~pcapkit.protocols.link.vlan.VLAN` Vendor Crawlers
================================================================

.. module:: pcapkit.vendor.vlan

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.link.vlan.VLAN` implementations. Available
vendor crawlers include:

.. list-table::

   * - :const:`VLAN_PriorityLevel <pcapkit.vendor.vlan.priority_level.PriorityLevel>`
     - Priority Levels [*]_

Priority levels defined in IEEE 802.1p
======================================

.. module:: pcapkit.vendor.vlan.priority_level

This module contains the vendor crawler for **Priority levels defined in IEEE 802.1p**,
which is automatically generating :class:`pcapkit.const.vlan.priority_level.PriorityLevel`.

.. autoclass:: pcapkit.vendor.vlan.priority_level.PriorityLevel
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IEEE_P802.1p#Priority_levels
