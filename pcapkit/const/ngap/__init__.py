# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.ngap.NGAP` Constant Enumerations
==============================================================================

.. module:: pcapkit.const.ngap

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.ngap.NGAP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`NGAP_ProcedureCode <pcapkit.const.ngap.procedure_code.ProcedureCode>`
     - NGAP Elementary Procedure Codes [*]_
   * - :class:`NGAP_ProtocolIE <pcapkit.const.ngap.protocol_ie.ProtocolIE>`
     - NGAP Protocol IE Identifiers [*]_

Both are automatically generated from
:mod:`pcapkit.vendor.ngap.procedure_code` and
:mod:`pcapkit.vendor.ngap.protocol_ie`, which source the assignment from
|pycrate|_'s compiled NGAP specification rather than a network registry --
see that module's docstring for why, and GitHub issue #880 for the ruling.

.. [*] 3GPP TS 38.413
.. [*] 3GPP TS 38.413

.. |pycrate| replace:: ``pycrate``
.. _pycrate: https://github.com/pycrate-org/pycrate

"""

from pcapkit.const.ngap.procedure_code import ProcedureCode as NGAP_ProcedureCode
from pcapkit.const.ngap.protocol_ie import ProtocolIE as NGAP_ProtocolIE

__all__ = ['NGAP_ProcedureCode', 'NGAP_ProtocolIE']
