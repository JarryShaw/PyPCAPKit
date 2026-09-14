=====================================================================
:class:`~pcapkit.protocols.transport.sctp.SCTP` Vendor Crawlers
=====================================================================

.. module:: pcapkit.vendor.sctp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.transport.sctp.SCTP` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`SCTP_Chunk <pcapkit.vendor.sctp.chunk.Chunk>`
     - SCTP Chunk Types [*]_
   * - :class:`SCTP_Parameter <pcapkit.vendor.sctp.parameter.Parameter>`
     - SCTP Chunk Parameter Types [*]_
   * - :class:`SCTP_CauseCode <pcapkit.vendor.sctp.cause_code.CauseCode>`
     - SCTP Error Cause Codes [*]_
   * - :class:`SCTP_PayloadProtocolIdentifier <pcapkit.vendor.sctp.payload_protocol_identifier.PayloadProtocolIdentifier>`
     - SCTP Payload Protocol Identifiers [*]_

SCTP Chunk Types
================

.. module:: pcapkit.vendor.sctp.chunk

This module contains the vendor crawler for **SCTP Chunk Types**,
which is automatically generating :class:`pcapkit.const.sctp.chunk.Chunk`.

.. autoclass:: pcapkit.vendor.sctp.chunk.Chunk
   :members: FLAG, LINK
   :show-inheritance:

SCTP Chunk Parameter Types
==========================

.. module:: pcapkit.vendor.sctp.parameter

This module contains the vendor crawler for **SCTP Chunk Parameter Types**,
which is automatically generating :class:`pcapkit.const.sctp.parameter.Parameter`.

.. autoclass:: pcapkit.vendor.sctp.parameter.Parameter
   :members: FLAG, LINK
   :show-inheritance:

SCTP Error Cause Codes
======================

.. module:: pcapkit.vendor.sctp.cause_code

This module contains the vendor crawler for **SCTP Error Cause Codes**,
which is automatically generating :class:`pcapkit.const.sctp.cause_code.CauseCode`.

.. autoclass:: pcapkit.vendor.sctp.cause_code.CauseCode
   :members: FLAG, LINK
   :show-inheritance:

SCTP Payload Protocol Identifiers
=================================

.. module:: pcapkit.vendor.sctp.payload_protocol_identifier

This module contains the vendor crawler for **SCTP Payload Protocol Identifiers**,
which is automatically generating :class:`pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`.

.. autoclass:: pcapkit.vendor.sctp.payload_protocol_identifier.PayloadProtocolIdentifier
   :members: FLAG, LINK
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-1
.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-2
.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-24
.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25
