====================================================================
:class:`~pcapkit.protocols.internet.igmp.IGMP` Constant Enumerations
====================================================================

.. module:: pcapkit.const.igmp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.internet.igmp.IGMP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`IGMP_Type <pcapkit.const.igmp.type.Type>`
     - IGMP Type Numbers [*]_
   * - :class:`IGMP_RecordType <pcapkit.const.igmp.record_type.RecordType>`
     - IGMP Group Record Types [*]_

IGMP Type Numbers
=================

.. module:: pcapkit.const.igmp.type

This module contains the constant enumeration for **IGMP Type Numbers**,
which is automatically generated from :class:`pcapkit.vendor.igmp.type.Type`.

.. autoclass:: pcapkit.const.igmp.type.Type
   :members:
   :undoc-members:
   :show-inheritance:

IGMP Group Record Types
========================

.. module:: pcapkit.const.igmp.record_type

This module contains the constant enumeration for **IGMP Group Record
Types**, which is automatically generated from
:class:`pcapkit.vendor.igmp.record_type.RecordType`.

.. autoclass:: pcapkit.const.igmp.record_type.RecordType
   :members:
   :undoc-members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml
.. [*] https://www.rfc-editor.org/rfc/rfc3376#section-4.2.12
