====================================================================
:class:`~pcapkit.protocols.application.ngap.NGAP` Vendor Crawlers
====================================================================

.. module:: pcapkit.vendor.ngap

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.application.ngap.NGAP` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`NGAP_ProcedureCode <pcapkit.vendor.ngap.procedure_code.ProcedureCode>`
     - NGAP Elementary Procedure Codes [*]_
   * - :class:`NGAP_ProtocolIE <pcapkit.vendor.ngap.protocol_ie.ProtocolIE>`
     - NGAP Protocol IE Identifiers [*]_

Both source the assignment from |pycrate|_'s already-installed, compiled NGAP
specification rather than fetching a network registry -- see the module
docstring below for why, and GitHub issue #880 for the ruling.

NGAP Elementary Procedure Codes
===============================

.. module:: pcapkit.vendor.ngap.procedure_code

This module contains the vendor crawler for **NGAP Elementary Procedure Codes**,
which is automatically generating :class:`pcapkit.const.ngap.procedure_code.ProcedureCode`.

.. autoclass:: pcapkit.vendor.ngap.procedure_code.ProcedureCode
   :members: FLAG, LINK
   :show-inheritance:

NGAP Protocol IE Identifiers
=============================

.. module:: pcapkit.vendor.ngap.protocol_ie

This module contains the vendor crawler for **NGAP Protocol IE Identifiers**,
which is automatically generating :class:`pcapkit.const.ngap.protocol_ie.ProtocolIE`.

.. autoclass:: pcapkit.vendor.ngap.protocol_ie.ProtocolIE
   :members: FLAG, LINK
   :show-inheritance:

.. rubric:: Footnotes

.. [*] 3GPP TS 38.413
.. [*] 3GPP TS 38.413

.. |pycrate| replace:: ``pycrate``
.. _pycrate: https://github.com/pycrate-org/pycrate
