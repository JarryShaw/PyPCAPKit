========================================================================
:class:`~pcapkit.protocols.application.ngap.NGAP` Constant Enumerations
========================================================================

.. module:: pcapkit.const.ngap

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.ngap.NGAP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`NGAP_ProcedureCode <pcapkit.const.ngap.procedure_code.ProcedureCode>`
     - NGAP Elementary Procedure Codes [*]_
   * - :class:`NGAP_ProtocolIE <pcapkit.const.ngap.protocol_ie.ProtocolIE>`
     - NGAP Protocol IE Identifiers [*]_

Both are automatically generated from |pycrate|_'s compiled NGAP
specification rather than an IANA-style registry -- see
:mod:`pcapkit.vendor.ngap.procedure_code`'s module docstring for why.

NGAP Elementary Procedure Codes
===============================

.. module:: pcapkit.const.ngap.procedure_code

This module contains the constant enumeration for **NGAP Elementary Procedure Codes**,
which is automatically generated from :class:`pcapkit.vendor.ngap.procedure_code.ProcedureCode`.

.. autoclass:: pcapkit.const.ngap.procedure_code.ProcedureCode
   :members:
   :undoc-members:
   :show-inheritance:

NGAP Protocol IE Identifiers
=============================

.. module:: pcapkit.const.ngap.protocol_ie

This module contains the constant enumeration for **NGAP Protocol IE Identifiers**,
which is automatically generated from :class:`pcapkit.vendor.ngap.protocol_ie.ProtocolIE`.

.. autoclass:: pcapkit.const.ngap.protocol_ie.ProtocolIE
   :members:
   :undoc-members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] 3GPP TS 38.413
.. [*] 3GPP TS 38.413

.. |pycrate| replace:: ``pycrate``
.. _pycrate: https://github.com/pycrate-org/pycrate
