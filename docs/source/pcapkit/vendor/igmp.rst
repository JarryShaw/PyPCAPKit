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
   * - :class:`IGMP_RecordType <pcapkit.vendor.igmp.record_type.RecordType>`
     - IGMP Group Record Types [*]_

IGMP Type Numbers
=================

.. module:: pcapkit.vendor.igmp.type

This module contains the vendor crawler for **IGMP Type Numbers**,
which is automatically generating :class:`pcapkit.const.igmp.type.Type`.

.. autoclass:: pcapkit.vendor.igmp.type.Type
   :members: FLAG, LINK
   :show-inheritance:

IGMP Group Record Types
========================

.. module:: pcapkit.vendor.igmp.record_type

This module contains the vendor crawler for **IGMP Group Record Types**,
which is automatically generating
:class:`pcapkit.const.igmp.record_type.RecordType`. Unlike the type-number
crawler above, this is not an IANA-maintained registry -- the six values are
fixed in :rfc:`3376#section-4.2.12` itself -- so :meth:`~pcapkit.vendor.igmp.record_type.RecordType.request`
returns the table directly rather than fetching :attr:`LINK`.

.. autoclass:: pcapkit.vendor.igmp.record_type.RecordType
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml
.. [*] https://www.rfc-editor.org/rfc/rfc3376#section-4.2.12
