=============================================================================
:class:`~pcapkit.protocols.application.ngap.protocol.NGAP` Vendor Crawlers
=============================================================================

.. module:: pcapkit.vendor.ngap

.. list-table::

   * - :class:`NGAP_ProcedureCode <pcapkit.vendor.ngap.procedure_code.ProcedureCode>`
     - NGAP Elementary Procedure Codes [*]_
   * - :class:`NGAP_ProtocolIE <pcapkit.vendor.ngap.protocol_ie.ProtocolIE>`
     - NGAP Protocol IE Identifiers [*]_

Each reads the assignment from |pycrate|_'s installed, compiled NGAP specification
rather than fetching a registry: 3GPP publishes TS 38.413 as a PDF, with no
registry kept in step with it (:issue:`880`).

NGAP Elementary Procedure Codes
===============================

.. module:: pcapkit.vendor.ngap.procedure_code

Generates :class:`pcapkit.const.ngap.procedure_code.ProcedureCode`.

.. autoclass:: pcapkit.vendor.ngap.procedure_code.ProcedureCode
   :members: FLAG, _request
   :show-inheritance:

NGAP Protocol IE Identifiers
=============================

.. module:: pcapkit.vendor.ngap.protocol_ie

Generates :class:`pcapkit.const.ngap.protocol_ie.ProtocolIE`.

.. autoclass:: pcapkit.vendor.ngap.protocol_ie.ProtocolIE
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] 3GPP TS 38.413
.. [*] 3GPP TS 38.413
