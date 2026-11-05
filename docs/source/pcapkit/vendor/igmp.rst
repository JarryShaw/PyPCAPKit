=======================================================================
:class:`~pcapkit.protocols.internet.igmp.protocol.IGMP` Vendor Crawlers
=======================================================================

.. module:: pcapkit.vendor.igmp

.. list-table::

   * - :class:`IGMP_Type <pcapkit.vendor.igmp.type.Type>`
     - IGMP Type Numbers [*]_
   * - :class:`IGMP_RecordType <pcapkit.vendor.igmp.record_type.RecordType>`
     - IGMP Group Record Types [*]_

.. versionadded:: 1.6.0

IGMP Type Numbers
=================

.. module:: pcapkit.vendor.igmp.type

Generates :class:`pcapkit.const.igmp.type.Type`.

.. autoclass:: pcapkit.vendor.igmp.type.Type
   :members: FLAG, LINK
   :show-inheritance:

IGMP Group Record Types
========================

.. module:: pcapkit.vendor.igmp.record_type

Generates :class:`pcapkit.const.igmp.record_type.RecordType`. The record types are
fixed in :rfc:`3376#section-4.2.12`, not kept in an IANA registry, so
:meth:`~pcapkit.vendor.igmp.record_type.RecordType.request` returns the module's
``DATA`` and the class defines no ``LINK``.

.. autoclass:: pcapkit.vendor.igmp.record_type.RecordType
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml
.. [*] https://www.rfc-editor.org/rfc/rfc3376#section-4.2.12
