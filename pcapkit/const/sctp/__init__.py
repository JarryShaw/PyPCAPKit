# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.transport.sctp.SCTP` Constant Enumerations
==========================================================================

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

.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-1
.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-2
.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-24
.. [*] https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25

Note:
    Unlike most constant enumerations of :mod:`pcapkit`, the SCTP enumerations
    are **hand-maintained**, as there is no crawler for them under
    :mod:`pcapkit.vendor` yet. Should one be added later, it would target the
    registries linked above.

"""

from pcapkit.const.sctp.cause_code import CauseCode as SCTP_CauseCode
from pcapkit.const.sctp.chunk import Chunk as SCTP_Chunk
from pcapkit.const.sctp.parameter import Parameter as SCTP_Parameter
from pcapkit.const.sctp.payload_protocol_identifier import \
    PayloadProtocolIdentifier as SCTP_PayloadProtocolIdentifier

__all__ = ['SCTP_Chunk', 'SCTP_Parameter', 'SCTP_CauseCode',
           'SCTP_PayloadProtocolIdentifier']
