# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6` Vendor Crawlers
=================================================================================

.. module:: pcapkit.vendor.icmpv6

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6` implementations. Available
enumerations include:

.. list-table::

   * - :class:`ICMPv6_Type <pcapkit.vendor.icmpv6.type.Type>`
     - ICMPv6 Type Numbers [*]_
   * - :class:`ICMPv6_DestinationUnreachableCode <pcapkit.vendor.icmpv6.destination_unreachable_code.DestinationUnreachableCode>`
     - ICMPv6 Destination Unreachable Codes [*]_
   * - :class:`ICMPv6_TimeExceededCode <pcapkit.vendor.icmpv6.time_exceeded_code.TimeExceededCode>`
     - ICMPv6 Time Exceeded Codes [*]_
   * - :class:`ICMPv6_ParameterProblemCode <pcapkit.vendor.icmpv6.parameter_problem_code.ParameterProblemCode>`
     - ICMPv6 Parameter Problem Codes [*]_
   * - :class:`ICMPv6_NDOption <pcapkit.vendor.icmpv6.nd_option.NDOption>`
     - IPv6 Neighbor Discovery Option Formats [*]_
   * - :class:`ICMPv6_RouterPreference <pcapkit.vendor.icmpv6.router_preference.RouterPreference>`
     - Router Selection Preferences [*]_

.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-types
.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-type-1
.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-type-3
.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-type-4
.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5
.. [*] https://www.rfc-editor.org/rfc/rfc4191.html#section-2.1

"""

from pcapkit.vendor.icmpv6.destination_unreachable_code import \
    DestinationUnreachableCode as ICMPv6_DestinationUnreachableCode
from pcapkit.vendor.icmpv6.nd_option import NDOption as ICMPv6_NDOption
from pcapkit.vendor.icmpv6.parameter_problem_code import \
    ParameterProblemCode as ICMPv6_ParameterProblemCode
from pcapkit.vendor.icmpv6.router_preference import RouterPreference as ICMPv6_RouterPreference
from pcapkit.vendor.icmpv6.time_exceeded_code import TimeExceededCode as ICMPv6_TimeExceededCode
from pcapkit.vendor.icmpv6.type import Type as ICMPv6_Type

__all__ = [
    'ICMPv6_Type',
    'ICMPv6_DestinationUnreachableCode', 'ICMPv6_TimeExceededCode', 'ICMPv6_ParameterProblemCode',
    'ICMPv6_NDOption', 'ICMPv6_RouterPreference',
]
