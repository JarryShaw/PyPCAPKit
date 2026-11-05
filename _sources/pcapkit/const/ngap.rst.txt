=================================================================================
:class:`~pcapkit.protocols.application.ngap.protocol.NGAP` Constant Enumerations
=================================================================================

.. module:: pcapkit.const.ngap

.. list-table::

   * - :class:`NGAP_ProcedureCode <pcapkit.const.ngap.procedure_code.ProcedureCode>`
     - NGAP Elementary Procedure Codes [*]_
   * - :class:`NGAP_ProtocolIE <pcapkit.const.ngap.protocol_ie.ProtocolIE>`
     - NGAP Protocol IE Identifiers [*]_

Each is generated from |pycrate|_'s compiled NGAP specification rather than an
IANA-style registry; :mod:`pcapkit.vendor.ngap` says why.

NGAP Elementary Procedure Codes
===============================

.. module:: pcapkit.const.ngap.procedure_code

Generated from :class:`pcapkit.vendor.ngap.procedure_code.ProcedureCode`.

.. autoclass:: pcapkit.const.ngap.procedure_code.ProcedureCode
   :members:
   :undoc-members:
   :show-inheritance:

NGAP Protocol IE Identifiers
=============================

.. module:: pcapkit.const.ngap.protocol_ie

Generated from :class:`pcapkit.vendor.ngap.protocol_ie.ProtocolIE`.

.. autoclass:: pcapkit.const.ngap.protocol_ie.ProtocolIE
   :members:
   :undoc-members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] 3GPP TS 38.413
.. [*] 3GPP TS 38.413
