=====================================================================
:class:`~pcapkit.protocols.transport.sctp.SCTP` Constant Enumerations
=====================================================================

.. module:: pcapkit.const.sctp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.transport.sctp.SCTP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`SCTP_Chunk <pcapkit.const.sctp.chunk.Chunk>`
     - SCTP Chunk Types [*]_
   * - :class:`SCTP_Parameter <pcapkit.const.sctp.parameter.Parameter>`
     - SCTP Chunk Parameter Types [*]_
   * - :class:`SCTP_CauseCode <pcapkit.const.sctp.cause_code.CauseCode>`
     - SCTP Error Cause Codes [*]_
   * - :class:`SCTP_PayloadProtocolIdentifier <pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier>`
     - SCTP Payload Protocol Identifiers [*]_

.. note::

   Unlike most constant enumerations of :mod:`pcapkit`, the SCTP enumerations
   are **hand-maintained**, as there is no crawler for them under
   :mod:`pcapkit.vendor` yet. Should one be added later, it would target the
   registries linked above.

SCTP Chunk Types
================

.. module:: pcapkit.const.sctp.chunk

This module contains the constant enumeration for **SCTP Chunk Types**,
which is maintained manually against the IANA registry, as there
is currently no vendor crawler for SCTP under :mod:`pcapkit.vendor`.

.. autoclass:: pcapkit.const.sctp.chunk.Chunk
   :members:
   :undoc-members:
   :show-inheritance:

SCTP Chunk Parameter Types
==========================

.. module:: pcapkit.const.sctp.parameter

This module contains the constant enumeration for **SCTP Chunk Parameter Types**,
which is maintained manually against the IANA registry, as there
is currently no vendor crawler for SCTP under :mod:`pcapkit.vendor`.

.. autoclass:: pcapkit.const.sctp.parameter.Parameter
   :members:
   :undoc-members:
   :show-inheritance:

SCTP Error Cause Codes
======================

.. module:: pcapkit.const.sctp.cause_code

This module contains the constant enumeration for **SCTP Error Cause Codes**,
which is maintained manually against the IANA registry, as there
is currently no vendor crawler for SCTP under :mod:`pcapkit.vendor`.

.. autoclass:: pcapkit.const.sctp.cause_code.CauseCode
   :members:
   :undoc-members:
   :show-inheritance:

SCTP Payload Protocol Identifiers
=================================

.. module:: pcapkit.const.sctp.payload_protocol_identifier

This module contains the constant enumeration for **SCTP Payload Protocol Identifiers**,
which is maintained manually against the IANA registry, as there
is currently no vendor crawler for SCTP under :mod:`pcapkit.vendor`.

.. autoclass:: pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier
   :members:
   :undoc-members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-1
.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-2
.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-24
.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25
