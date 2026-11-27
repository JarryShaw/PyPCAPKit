===========================================================================
:class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6` Vendor Crawlers
===========================================================================

.. module:: pcapkit.vendor.icmpv6

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

.. versionadded:: 1.6.0

ICMPv6 Type Numbers
====================

.. module:: pcapkit.vendor.icmpv6.type

Generates :class:`pcapkit.const.icmpv6.type.Type`.

.. autoclass:: pcapkit.vendor.icmpv6.type.Type
   :members: FLAG
   :show-inheritance:

ICMPv6 Destination Unreachable Codes
======================================

.. module:: pcapkit.vendor.icmpv6.destination_unreachable_code

Generates :class:`pcapkit.const.icmpv6.destination_unreachable_code.DestinationUnreachableCode`.

.. autoclass:: pcapkit.vendor.icmpv6.destination_unreachable_code.DestinationUnreachableCode
   :members: FLAG
   :show-inheritance:

ICMPv6 Time Exceeded Codes
============================

.. module:: pcapkit.vendor.icmpv6.time_exceeded_code

Generates :class:`pcapkit.const.icmpv6.time_exceeded_code.TimeExceededCode`.

.. autoclass:: pcapkit.vendor.icmpv6.time_exceeded_code.TimeExceededCode
   :members: FLAG
   :show-inheritance:

ICMPv6 Parameter Problem Codes
================================

.. module:: pcapkit.vendor.icmpv6.parameter_problem_code

Generates :class:`pcapkit.const.icmpv6.parameter_problem_code.ParameterProblemCode`.

.. autoclass:: pcapkit.vendor.icmpv6.parameter_problem_code.ParameterProblemCode
   :members: FLAG
   :show-inheritance:

IPv6 Neighbor Discovery Option Formats
=======================================

.. module:: pcapkit.vendor.icmpv6.nd_option

.. versionadded:: 1.9.0

Generates :class:`pcapkit.const.icmpv6.nd_option.NDOption`.

.. autoclass:: pcapkit.vendor.icmpv6.nd_option.NDOption
   :members: FLAG
   :show-inheritance:

Router Selection Preferences
=============================

.. module:: pcapkit.vendor.icmpv6.router_preference

.. versionadded:: 1.9.0

Generates :class:`pcapkit.const.icmpv6.router_preference.RouterPreference`.

.. autoclass:: pcapkit.vendor.icmpv6.router_preference.RouterPreference
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-types
.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-type-1
.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-type-3
.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-type-4
.. [*] https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5
.. [*] https://www.rfc-editor.org/rfc/rfc4191.html#section-2.1
