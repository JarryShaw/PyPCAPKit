# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.transport.sctp.SCTP` Vendor Crawlers
=====================================================================

.. module:: pcapkit.vendor.sctp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.transport.sctp.SCTP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`SCTP_Chunk <pcapkit.vendor.sctp.chunk.Chunk>`
     - SCTP Chunk Types [*]_
   * - :class:`SCTP_Parameter <pcapkit.vendor.sctp.parameter.Parameter>`
     - SCTP Chunk Parameter Types [*]_
   * - :class:`SCTP_CauseCode <pcapkit.vendor.sctp.cause_code.CauseCode>`
     - SCTP Error Cause Codes [*]_
   * - :class:`SCTP_PayloadProtocolIdentifier <pcapkit.vendor.sctp.payload_protocol_identifier.PayloadProtocolIdentifier>`
     - SCTP Payload Protocol Identifiers [*]_

.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-1
.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-2
.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-24
.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25

"""

from pcapkit.vendor.sctp.cause_code import CauseCode as SCTP_CauseCode
from pcapkit.vendor.sctp.chunk import Chunk as SCTP_Chunk
from pcapkit.vendor.sctp.parameter import Parameter as SCTP_Parameter
from pcapkit.vendor.sctp.payload_protocol_identifier import \
    PayloadProtocolIdentifier as SCTP_PayloadProtocolIdentifier

__all__ = ['SCTP_Chunk', 'SCTP_Parameter', 'SCTP_CauseCode',
           'SCTP_PayloadProtocolIdentifier']
