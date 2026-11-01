==================================================================
:class:`~pcapkit.protocols.internet.icmpv4.ICMPv4` Vendor Crawlers
==================================================================

.. module:: pcapkit.vendor.icmp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.icmpv4.ICMPv4` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`ICMP_Type <pcapkit.vendor.icmp.type.Type>`
     - ICMP Type Numbers [*]_
   * - :class:`ICMP_DestinationUnreachableCode <pcapkit.vendor.icmp.destination_unreachable_code.DestinationUnreachableCode>`
     - ICMP Destination Unreachable Codes [*]_
   * - :class:`ICMP_TimeExceededCode <pcapkit.vendor.icmp.time_exceeded_code.TimeExceededCode>`
     - ICMP Time Exceeded Codes [*]_
   * - :class:`ICMP_ParameterProblemCode <pcapkit.vendor.icmp.parameter_problem_code.ParameterProblemCode>`
     - ICMP Parameter Problem Codes [*]_

ICMP Type Numbers
=================

.. module:: pcapkit.vendor.icmp.type

This module contains the vendor crawler for **ICMP Type Numbers**,
which is automatically generating :class:`pcapkit.const.icmp.type.Type`.

.. autoclass:: pcapkit.vendor.icmp.type.Type
   :members: FLAG
   :show-inheritance:

ICMP Destination Unreachable Codes
===================================

.. module:: pcapkit.vendor.icmp.destination_unreachable_code

This module contains the vendor crawler for **ICMP Destination Unreachable
Codes**, which is automatically generating
:class:`pcapkit.const.icmp.destination_unreachable_code.DestinationUnreachableCode`.

.. autoclass:: pcapkit.vendor.icmp.destination_unreachable_code.DestinationUnreachableCode
   :members: FLAG
   :show-inheritance:

ICMP Time Exceeded Codes
=========================

.. module:: pcapkit.vendor.icmp.time_exceeded_code

This module contains the vendor crawler for **ICMP Time Exceeded Codes**,
which is automatically generating
:class:`pcapkit.const.icmp.time_exceeded_code.TimeExceededCode`.

.. autoclass:: pcapkit.vendor.icmp.time_exceeded_code.TimeExceededCode
   :members: FLAG
   :show-inheritance:

ICMP Parameter Problem Codes
==============================

.. module:: pcapkit.vendor.icmp.parameter_problem_code

This module contains the vendor crawler for **ICMP Parameter Problem
Codes**, which is automatically generating
:class:`pcapkit.const.icmp.parameter_problem_code.ParameterProblemCode`.

.. autoclass:: pcapkit.vendor.icmp.parameter_problem_code.ParameterProblemCode
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types
.. [*] https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes
.. [*] https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes
.. [*] https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes
