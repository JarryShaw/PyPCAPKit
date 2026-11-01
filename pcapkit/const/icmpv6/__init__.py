# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.icmpv6.ICMPv6` Constant Enumerations
===============================================================================

.. module:: pcapkit.const.icmpv6

This module contains all constant enumerations of
:class:`~pcapkit.protocols.internet.icmpv6.ICMPv6` implementations. Available
enumerations include:

.. list-table::

   * - :class:`ICMPv6_Type <pcapkit.const.icmpv6.type.Type>`
     - ICMPv6 Type Numbers [*]_
   * - :class:`ICMPv6_DestinationUnreachableCode <pcapkit.const.icmpv6.destination_unreachable_code.DestinationUnreachableCode>`
     - ICMPv6 Destination Unreachable Codes [*]_
   * - :class:`ICMPv6_TimeExceededCode <pcapkit.const.icmpv6.time_exceeded_code.TimeExceededCode>`
     - ICMPv6 Time Exceeded Codes [*]_
   * - :class:`ICMPv6_ParameterProblemCode <pcapkit.const.icmpv6.parameter_problem_code.ParameterProblemCode>`
     - ICMPv6 Parameter Problem Codes [*]_

.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-types
.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-type-1
.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-type-3
.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-type-4

"""

from pcapkit.const.icmpv6.destination_unreachable_code import \
    DestinationUnreachableCode as ICMPv6_DestinationUnreachableCode
from pcapkit.const.icmpv6.parameter_problem_code import \
    ParameterProblemCode as ICMPv6_ParameterProblemCode
from pcapkit.const.icmpv6.time_exceeded_code import TimeExceededCode as ICMPv6_TimeExceededCode
from pcapkit.const.icmpv6.type import Type as ICMPv6_Type

__all__ = [
    'ICMPv6_Type',
    'ICMPv6_DestinationUnreachableCode', 'ICMPv6_TimeExceededCode', 'ICMPv6_ParameterProblemCode',
]
