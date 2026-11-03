# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.icmpv4.ICMPv4` Constant Enumerations
==============================================================================

.. module:: pcapkit.const.icmp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.internet.icmpv4.ICMPv4` implementations. Available
enumerations include:

.. list-table::

   * - :class:`ICMP_Type <pcapkit.const.icmp.type.Type>`
     - ICMP Type Numbers [*]_
   * - :class:`ICMP_DestinationUnreachableCode <pcapkit.const.icmp.destination_unreachable_code.DestinationUnreachableCode>`
     - ICMP Destination Unreachable Codes [*]_
   * - :class:`ICMP_TimeExceededCode <pcapkit.const.icmp.time_exceeded_code.TimeExceededCode>`
     - ICMP Time Exceeded Codes [*]_
   * - :class:`ICMP_ParameterProblemCode <pcapkit.const.icmp.parameter_problem_code.ParameterProblemCode>`
     - ICMP Parameter Problem Codes [*]_

.. [*] https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types
.. [*] https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes
.. [*] https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes
.. [*] https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.lazy import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.icmp.destination_unreachable_code import \
        DestinationUnreachableCode as ICMP_DestinationUnreachableCode
    from pcapkit.const.icmp.parameter_problem_code import \
        ParameterProblemCode as ICMP_ParameterProblemCode
    from pcapkit.const.icmp.time_exceeded_code import TimeExceededCode as ICMP_TimeExceededCode
    from pcapkit.const.icmp.type import Type as ICMP_Type

__all__ = [
    'ICMP_Type',
    'ICMP_DestinationUnreachableCode', 'ICMP_TimeExceededCode', 'ICMP_ParameterProblemCode',
]

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'ICMP_Type': ('type', 'Type'),
    'ICMP_DestinationUnreachableCode': ('destination_unreachable_code', 'DestinationUnreachableCode'),
    'ICMP_TimeExceededCode': ('time_exceeded_code', 'TimeExceededCode'),
    'ICMP_ParameterProblemCode': ('parameter_problem_code', 'ParameterProblemCode'),
})
