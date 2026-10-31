==============================================================
:class:`~pcapkit.protocols.internet.igmp.IGMP` Vendor Crawlers
==============================================================

.. module:: pcapkit.vendor.igmp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.igmp.IGMP` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`IGMP_Type <pcapkit.vendor.igmp.type.Type>`
     - IGMP Type Numbers [*]_

IGMP Type Numbers
=================

.. module:: pcapkit.vendor.igmp.type

This module contains the vendor crawler for **IGMP Type Numbers**,
which is automatically generating :class:`pcapkit.const.igmp.type.Type`.

.. autoclass:: pcapkit.vendor.igmp.type.Type
   :members: FLAG, LINK
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml
